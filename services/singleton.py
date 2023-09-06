class Singleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Singleton, cls).__new__(cls)
            cls._instance.token = None
            cls._instance.userId = None
            cls._instance.customerId = None
            cls._instance.isFundmanager = None
            cls._instance.values = {}
            cls._instance.data = {}  # Create an empty dictionary to hold various endpoint data
        return cls._instance