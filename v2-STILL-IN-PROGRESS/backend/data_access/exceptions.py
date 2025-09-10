# exceptions.py
class DatabaseOperationError(Exception):
    """Raised when a database operation fails"""
    pass

class DatabaseIntegrityError(Exception):
    """Raised when database integrity is violated"""
    pass
