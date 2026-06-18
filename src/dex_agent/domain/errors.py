class AgentException(Exception):
    pass

class ToolNotFoundError(AgentException):
    pass

class InvalidTaskError(AgentException):
    pass

class InvalidClassFormatError(AgentException):
    pass

class TaskExecutionError(AgentException):
    pass
