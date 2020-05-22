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
        }
        try:
            wordlist_fn = jmp_table[kind]
        except KeyError:
            ctx.log.error(f'unknown option: {kind} (see log for options)')
            ctx.log.info(f'available options are {", ".join(jmp_table)}')

        result = wordlist_fn(flows)
        ctx.log.info(f'params: {result}')

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
