from django.db.models import Count, Avg, F, ExpressionWrapper, fields
from django.db.models.functions import ExtractDay
from django.utils import timezone

from . import models
from .models import SHEObservation, ObservationAnalytics
from datetime import timedelta
import json


class ObservationAnalyticsCalculator:
    @staticmethod
    def calculate_department_analytics(department, date=None):
        """Calculate analytics for a specific department and date."""
        if date is None:
            date = timezone.now().date()

        # Base queryset for the department
        queryset = SHEObservation.objects.filter(department=department)

        # Calculate basic counts
        total_observations = queryset.count()
        open_observations = queryset.exclude(status='closed').count()
        closed_observations = queryset.filter(status='closed').count()

        # Calculate average resolution time for closed observations
        closed_obs = queryset.filter(status='closed')
        avg_resolution_time = None
        if closed_obs.exists():
            resolution_time = ExpressionWrapper(
                F('updated_at') - F('created_at'),
                output_field=fields.DurationField()
            )
            avg_resolution_time = closed_obs.aggregate(
                avg_time=Avg(resolution_time)
            )['avg_time']

        # Calculate recurring issues
        recurring_issues = list(queryset.values('nature_of_issue')
                                .annotate(count=Count('id'))
                                .filter(count__gt=1)
                                .order_by('-count')[:5])

        # Additional analytics for charts
        analytics_data = {
            'basic_metrics': {
                'total_observations': total_observations,
                'open_observations': open_observations,
                'closed_observations': closed_observations,
            },
            'issue_types_distribution': list(
                queryset.values('issue_type')
                .annotate(count=Count('id'))
                .order_by('issue_type')
            ),
            'priority_distribution': list(
                queryset.values('priority')
                .annotate(count=Count('id'))
                .order_by('priority')
            ),
            'status_distribution': list(
                queryset.values('status')
                .annotate(count=Count('id'))
                .order_by('status')
            ),
            'monthly_trend': list(
                queryset.extra(select={'month': "DATE_TRUNC('month', date)"})
                .values('month')
                .annotate(count=Count('id'))
                .order_by('month')
            ),
            'average_resolution_by_priority': list(
                queryset.filter(status='closed')
                .values('priority')
                .annotate(
                    avg_days=ExpressionWrapper(
                        Avg(ExtractDay(F('updated_at') - F('created_at'))),
                        output_field=fields.FloatField()
                    )
                )
                .order_by('priority')
            ),
            'area_distribution': list(
                queryset.exclude(area='')
                .values('area')
                .annotate(count=Count('id'))
                .order_by('-count')
            ),
            'time_series': {
                'daily': list(
                    queryset.values('date')
                    .annotate(count=Count('id'))
                    .order_by('date')
                ),
                'weekly': list(
                    queryset.extra(select={'week': "DATE_TRUNC('week', date)"})
                    .values('week')
                    .annotate(count=Count('id'))
                    .order_by('week')
                )
            },
            'comparative': {
                'department_comparison': list(
                    SHEObservation.objects.values('department')
                    .annotate(
                        total=Count('id'),
                        open=Count('id', filter=models.Q(status__in=['pending', 'in_progress'])),
                        closed=Count('id', filter=models.Q(status='closed'))
                    )
                    .order_by('department')
                ),
                'issue_type_by_department': list(
                    SHEObservation.objects.values('department', 'issue_type')
                    .annotate(count=Count('id'))
                    .order_by('department', 'issue_type')
                )
            },
            'performance': {
                'resolution_time_trend': list(
                    queryset.filter(status='closed')
                    .extra(select={'month': "DATE_TRUNC('month', date)"})
                    .values('month')
                    .annotate(
                        avg_days=ExpressionWrapper(
                            Avg(ExtractDay(F('updated_at') - F('created_at'))),
                            output_field=fields.FloatField()
                        )
                    )
                    .order_by('month')
                ),
                'priority_distribution_trend': list(
                    queryset.extra(select={'month': "DATE_TRUNC('month', date)"})
                    .values('month', 'priority')
                    .annotate(count=Count('id'))
                    .order_by('month', 'priority')
                )
            }
        }

        return analytics_data

    @staticmethod
    def get_chart_data(department=None, start_date=None, end_date=None):
        """Get formatted data for various charts."""
        queryset = SHEObservation.objects
        if department:
            queryset = queryset.filter(department=department)
        if start_date:
            queryset = queryset.filter(date__gte=start_date)
        if end_date:
            queryset = queryset.filter(date__lte=end_date)

        return {
            'time_series': {
                'daily': list(
                    queryset.values('date')
                    .annotate(count=Count('id'))
                    .order_by('date')
                ),
                'weekly': list(
                    queryset.extra(select={'week': "DATE_TRUNC('week', date)"})
                    .values('week')
                    .annotate(count=Count('id'))
                    .order_by('week')
                )
            },
            'comparative': {
                'department_comparison': list(
                    queryset.values('department')
                    .annotate(
                        total=Count('id'),
                        open=Count('id', filter=models.Q(status__in=['pending', 'in_progress'])),
                        closed=Count('id', filter=models.Q(status='closed'))
                    )
                    .order_by('department')
                ),
                'issue_type_by_department': list(
                    queryset.values('department', 'issue_type')
                    .annotate(count=Count('id'))
                    .order_by('department', 'issue_type')
                )
            },
            'performance': {
                'resolution_time_trend': list(
                    queryset.filter(status='closed')
                    .extra(select={'month': "DATE_TRUNC('month', date)"})
                    .values('month')
                    .annotate(
                        avg_days=ExpressionWrapper(
                            Avg(ExtractDay(F('updated_at') - F('created_at'))),
                            output_field=fields.FloatField()
                        )
                    )
                    .order_by('month')
                )
            }
        }