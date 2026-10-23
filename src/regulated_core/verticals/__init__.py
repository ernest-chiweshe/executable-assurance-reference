"""Reference verticals: two strict (health, finance) + one forgiving (course). Pure additions."""
from .health import HealthPolicy
from .finance import FinancePolicy
from .course import CoursePolicy

__all__ = ["HealthPolicy", "FinancePolicy", "CoursePolicy"]
