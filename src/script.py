class Script:
    def __init__(self) -> None:
        pass

    def parse(self, stream):
        raise NotImplementedError

    def serialize(self):
        raise NotImplementedError
