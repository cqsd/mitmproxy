import codecs
import json

from typing import Optional

from mitmproxy.contentviews import base


def pretty_graphql(s: bytes) -> Optional[bytes]:
    try:
        o = json.loads(s.decode('utf-8'))
        query = codecs.encode(
            o['query'],
            'latin-1'
        ).decode('unicode_escape')
        variables = json.dumps(o['variables'], sort_keys=True, indent=2)
        return f'{query}\n{variables}'.encode('utf-8', 'strict')
    except (KeyError, ValueError):
        return None


class ViewGraphQL(base.View):
    name = 'GraphQL'
    content_types = []

    def __call__(self, data, **metadata):
        pg = pretty_graphql(data)
        if pg:
            return self.name, base.format_text(pg)
