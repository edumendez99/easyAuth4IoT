import calendar
from datetime import datetime

def init_filters(app):
    """Initialize custom template filters."""
    
    @app.template_filter('month_name')
    def month_name(month_number):
        """Convert month number to month name."""
        try:
            return calendar.month_name[int(month_number)]
        except (ValueError, IndexError):
            return str(month_number)
    
    @app.template_filter('format_datetime')
    def format_datetime(value, format='%Y-%m-%d %H:%M'):
        """Format a datetime object."""
        if value is None:
            return ""
        return value.strftime(format)
