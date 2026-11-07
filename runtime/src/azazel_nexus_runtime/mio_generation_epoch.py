"""Optional private caller epoch; legacy verbs/arguments remain valid unchanged."""
from .protocol import Argument, ArgumentKind, Verb


class EpochVerb(Verb):
    """Closed extension for the four internal generation transport operations.

    The protocol's ordinary Verb stays strict. No arbitrary optional arguments,
    principal claims or payload fields are accepted by this extension.
    """
    optional_arguments = (Argument('caller_epoch', ArgumentKind.IDENTIFIER),)

    def bind(self, raw):
        base = {key: value for key, value in raw.items() if key != 'caller_epoch'}
        result = super().bind(base)
        if 'caller_epoch' in raw:
            result['caller_epoch'] = self.optional_arguments[0].coerce(raw['caller_epoch'])
        return result
