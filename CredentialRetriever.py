from abc import ABC, abstractmethod

class CredentialRetriever(ABC):

    @abstractmethod
    def getCredential(self, username, **kwargs):
        pass

    @abstractmethod
    def getConfig(self):
        pass
