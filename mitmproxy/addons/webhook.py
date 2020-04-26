import asyncio
import json
import typing
import urllib.request

from mitmproxy import flowfilter
from mitmproxy import exceptions
from mitmproxy import ctx
# from mitmproxy.io import tnetstring  # TODO dump whole state (.dumps(..))


def http_post(url, _data):
    # this doesn't work btw, socket operations block so this is not async
    try:
        data = json.dumps(_data).encode('utf-8')  # XXX
        urllib.request.urlopen(urllib.request.Request(url, data))
    except Exception as e:
        ctx.log.error(e)


async def webhook_worker(url, queue, basic_auth: typing.Optional[str] = None):
    _data = await queue.get()  # bruh
    http_post(url, _data)


class Webhook:
    def __init__(self):
        self.filt = None
        self._queue = asyncio.Queue()

    def load(self, loader):
        loader.add_option(
            'webhook.url', typing.Optional[str], None,
            'where to send matching flows'
        )

        loader.add_option(
            'webhook.filter', typing.Optional[str], None,
            'filter expression'
        )

        loader.add_option(
            'webhook.max_concurrent', typing.Optional[int], 10,
            'maximum concurrent outgoing webhooks'
        )

    def configure(self, updated):
        if 'webhook.filter' in updated:
            filter_pattern = getattr(ctx.options, 'webhook.filter')
            self.filt = flowfilter.parse(filter_pattern)
            if not self.filt:
                raise exceptions.OptionsError(
                    "Invalid filter: %s" % filter_pattern
                )

    async def _process_flow(self, f):
        webhook_url = getattr(ctx.options, 'webhook.url')
        if self.filt and webhook_url:
            should_send_webhook = all([
                self.filt(f),
                not f.request.is_replay,
            ])
            if should_send_webhook:
                ctx.log.info(f'{__file__}: {len(asyncio.all_tasks())}')
                fields = ['scheme', 'pretty_host', 'port', 'path']
                payload = {
                    k: getattr(f.request, k)
                    for k in fields
                }
                # dunno what this is doing, might have to roll one myself
                http_post(webhook_url, payload)

    def process_flow(self, f):
        asyncio.get_event_loop().create_task(self._process_flow(f))

    def request(self, f):
        self.process_flow(f)

    def response(self, f):
        self.process_flow(f)
