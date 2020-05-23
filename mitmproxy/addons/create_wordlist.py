import json
import os.path
import typing

import mitmproxy.types

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow


def walk(d: dict) -> typing.Generator[dict, typing.Any, typing.Any]:
    '''Walk a dict tree to its leaves, yielding leaf keys and values. Ignore
    intermediate keys.
    '''
    for k, v in d.items():
        if not isinstance(v, dict):
            yield k, v
        else:
            yield from walk(v)


def open_file(path):
    '''copied from the save command i think'''
    if path.startswith("+"):
        path = path[1:]
        mode = "ab"
    else:
        mode = "wb"
    path = os.path.expanduser(path)
    return open(path, mode)


# use like this: wordlist <selection> <type> [path]
# example: wordlist @shown param /tmp/params.json
class CreateWordlist:
    @command.command('wordlist')
    def dispatch(self, flows: typing.Sequence[flow.Flow], kind: str,
                 path: mitmproxy.types.Path) -> None:
        jmp_table = {
            'query': self.wordlist_query,
            'param': self.wordlist_query,   # alias
            'params': self.wordlist_query,  # alias
            'form': self.wordlist_form_body,
            'json': self.wordlist_json_body,
            'graphql': self.wordlist_graphql_responses,
        }
        try:
            wordlist_fn = jmp_table[kind]
        except KeyError:
            ctx.log.error(f'unknown option: {kind} (see log for options)')
            ctx.log.info(f'available options are {", ".join(jmp_table)}')

        result = wordlist_fn(flows)
        if len(result):
            result_s = json.dumps(
                result,
                sort_keys=True,
                indent='  '
            ).encode('utf-8', 'strict')
            with open_file(path) as out:
                n_bytes = out.write(result_s)
                ctx.log.alert(f'wrote {n_bytes} to {path}')
        else:
            ctx.log.alert(f'no parameters found... try another option or check your selection')

    def wordlist_query(self, flows: typing.Sequence[flow.Flow]) -> dict:
        '''Make a collection of all query parameters in the selected flows.'''
        acc = {}
        # XXX the way mitmproxy parses queries is "too correct"---request.query
        # is a dict-like object where the values are the *first value* of a
        # param seen. for example: ?a=foo&a=bar => { a: foo }.
        #
        # however, some servers would interpret that as { a: foobar } so
        # eventually when you test something like that (i think some of the
        # windoze shit does this), you'll need to write custom parsing logic that
        # handles this "incorrectly"
        for f in flows:
            for k, v in f.request.query.items():
                if k not in acc:
                    acc[k] = []
                # this can be empty string fyi, but that's probably desirable to keep
                acc[k].append(v)

        # dedupe
        for k, v in acc.items():
            acc[k] = list(set(v))

        return acc

    def wordlist_form_body(self, flows: typing.Sequence[flow.Flow]) -> dict:
        '''Make a collection of all form-encoded fields in the selected flows.'''
        ctx.log.warn('unimplemented')
        return {}

    def wordlist_json_body(self, flows: typing.Sequence[flow.Flow]) -> dict:
        '''Make a collection of all LEAF VALUES of json in the selected flows. This ignores
        intermediate keys in nested json...'''
        ctx.log.warn('unimplemented')
        return {}

    def wordlist_graphql_responses(self, flows: typing.List[flow.Flow]) -> dict:
        # adding a placeholder 'fields' key makes the type dict fully recursive.
        # note that "fields" here really means mutations or queries, and we don't
        # know which (it turned out to be way easier to build up the schema dict by
        # mutating rather than by bubbling up a result)
        schema = {'fields': {}}

        UNKNOWN = 'UNKNOWN'
        KIND_TYPE = 'TYPE'
        KIND_ARRAY = 'ARRAY'
        KIND_UNION = 'UNION'
        KIND_SCALAR = 'SCALAR'  # i think this is supposd to be a type actually? idr

        def walk_collect(acc: dict, d: dict):
            for k, v in d.items():
                if isinstance(v, dict):
                    # no objects can be scalars. if it's a json object, then it's
                    # definitely a custom type
                    typename = v.get('__typename', k)
                    # add the type to the top level schema if it's not there yet
                    if typename not in schema:
                        schema[typename] = {
                            'fields': {},
                        }

                    # this next bit has a side effect of adding the return types of
                    # all queries and mutations to the top level schema's
                    # "fields", which is actually pretty nice. It's just that,
                    # since we're not inspecting the request side, we can't tell
                    # what's a query and what's a mutation---you'll have to look
                    # in your own logs for that one or submit a big-ass PR
                    if k not in acc['fields']:
                        acc['fields'][k] = {'kind': KIND_TYPE, 'typename': typename}
                    else:
                        field = acc['fields'][k]
                        if field['kind'] == KIND_UNION:
                            if typename not in field['types']:
                                field['types'].append(typename)
                        # if we've already seen this field before, then we have to
                        # check if it's actually a union type. the way to tell is
                        # simply this: if the current typename is different than
                        # what we've seen before, assume it's a union
                        #
                        # NB: i'm not sure if you can have a union of a type
                        # and an array, if so this can't handle that lol
                        elif field['kind'] == KIND_TYPE and typename != field['typename']:
                            # convert the single-type field to a union field with a
                            # list of possible types
                            field = {
                                'kind': KIND_UNION,
                                'types': [field['typename'], typename]
                            }
                    walk_collect(schema[typename], v)

                elif isinstance(v, list):
                    # if you hit this same field multiple times, you'll overwrite
                    # previous runs. We should only try to infer the type on subsequent
                    # runs if we were unable to determine the type the first time around
                    if k in acc['fields'] and acc['fields'][k]['of'] != UNKNOWN:
                        continue
                    # try to find the type of the array contents. this is kinda
                    # lame but the only real way to tell what the type of the
                    # contents of an array is... is to peek into the array.
                    # Note that this also needs to handle sum types. Refactor
                    # "opportunity"
                    if v:
                        if isinstance(v[0], dict):
                            typename = v[0].get('__typename', UNKNOWN)
                            acc['fields'][k] = {'kind': KIND_ARRAY, 'of': typename}
                        else:
                            acc['fields'][k] = {'kind': KIND_ARRAY, 'of': KIND_SCALAR}  # XXX should be type?
                    else:
                        acc['fields'][k] = {'kind': KIND_ARRAY, 'of': UNKNOWN}

                    # this assumes that the array is homogenous, but you can
                    # actually have unions in arrays
                    # HACK! if the array doesn't obviously contain types, then don't
                    # try to infer deeper (in fact, this means we always drop array
                    # values! fix this!!!!) XXX FIXME TODO
                    if acc['fields'][k]['of'] != KIND_SCALAR:
                        for el in v:
                            walk_collect(acc, el)

                else:
                    # we handle the __typename field separately above
                    if k == '__typename':
                        continue
                    # if there's no value for this leaf, we can't tell what kind of
                    # value it's supposed to be
                    kind = (v is None) and UNKNOWN or KIND_SCALAR
                    fields = acc['fields']
                    if k not in fields:
                        fields[k] = {'kind': kind, 'values': []}
                    # it's easier to use a list here than a set but probably a lot slower
                    if v is not None and v not in fields[k]['values']:
                        fields[k]['values'].append(v)

        for f in flows:
            try:
                data = json.loads(f.response.content.decode('utf-8'))['data'] or {}
                if isinstance(data, dict):
                    walk_collect(schema, data)
            except (KeyError, ValueError):
                pass
            except Exception as e:
                ctx.log.info(f.response.content)
                ctx.log.error(e)

        # we can't know whether the resolvers are queries or mutations without also
        # processing the request side of the flow, which i'm not about to do. PRs
        # welcome
        return {
            'types': schema,
            'resolvers': schema.pop('fields')
        }
