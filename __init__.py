from server import PromptServer

from .integration import install


NODE_CLASS_MAPPINGS = {}
_integration = install(PromptServer.instance)
