# Example OPA policy for AWS budgets and cost limits
package terraform.budget_control

import input.plan as tfplan

# Budget requirements by environment
budget_requirements = {
    "prod": {
        "max_monthly_budget": 10000,
        "alert_threshold_percentage": 80,
        "require_forecasting": true,
        "max_forecast_threshold": 110,
        "required_cost_filters": ["Service", "TagKeyValue"],
        "excluded_services": ["AWS Support (Developer)", "AWS Support (Business)"]
    },
    "staging": {
        "max_monthly_budget": 5000,
        "alert_threshold_percentage": 70,
        "require_forecasting": true,
        "max_forecast_threshold": 100,
        "required_cost_filters": ["Service"],
        "excluded_services": ["AWS Support (Developer)"]
    },
    "dev": {
        "max_monthly_budget": 1000,
        "alert_threshold_percentage": 60,
        "require_forecasting": false,
        "max_forecast_threshold": 100,
        "required_cost_filters": [],
        "excluded_services": []
    }
}

# Deny budgets exceeding maximum allowed amount
deny_large_budget[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    budget_limit := to_number(budget.change.after.limit_amount)
    max_limit := budget_requirements[env].max_monthly_budget
    
    budget_limit > max_limit
    
    msg = sprintf(
        "Budget amount %v exceeds maximum allowed budget of %v for %v environment",
        [budget_limit, max_limit, env]
    )
}

# Deny missing alert thresholds
deny_missing_alerts[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    required_threshold := budget_requirements[env].alert_threshold_percentage
    not has_alert_threshold(budget.change.after.notification, required_threshold)
    
    msg = sprintf(
        "Budget must have alert notification at %v%% threshold in %v environment",
        [required_threshold, env]
    )
}

# Helper to check alert thresholds
has_alert_threshold(notifications, threshold) {
    notification = notifications[_]
    threshold_value := to_number(notification.threshold)
    threshold_value <= threshold
}

# Deny missing cost filters
deny_missing_cost_filters[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    required_filter = budget_requirements[env].required_cost_filters[_]
    not budget.change.after.cost_filters[required_filter]
    
    msg = sprintf(
        "Budget must include cost filter for %v in %v environment",
        [required_filter, env]
    )
}

# Deny missing forecasting
deny_missing_forecasting[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    budget_requirements[env].require_forecasting
    not has_forecast_notification(budget.change.after.notification)
    
    msg = sprintf(
        "Budget must include forecasting notifications in %v environment",
        [env]
    )
}

# Helper to check forecast notifications
has_forecast_notification(notifications) {
    notification = notifications[_]
    notification.notification_type == "FORECASTED"
}

# Deny high forecast thresholds
deny_high_forecast_threshold[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    notification = budget.change.after.notification[_]
    notification.notification_type == "FORECASTED"
    
    threshold := to_number(notification.threshold)
    max_threshold := budget_requirements[env].max_forecast_threshold
    
    threshold > max_threshold
    
    msg = sprintf(
        "Forecast threshold %v%% exceeds maximum allowed threshold of %v%% in %v environment",
        [threshold, max_threshold, env]
    )
}

# Deny excluded services in budget
deny_excluded_services[msg] {
    budget = tfplan.resource_changes[_]
    budget.type == "aws_budgets_budget"
    env = budget.change.after.tags.Environment
    
    service = budget_requirements[env].excluded_services[_]
    budget.change.after.cost_filters.Service == service
    
    msg = sprintf(
        "Service %v should be excluded from budget in %v environment",
        [service, env]
    )
}

# Main deny rule combining all budget control policies
deny[msg] {
    msg = deny_large_budget[_]
} {
    msg = deny_missing_alerts[_]
} {
    msg = deny_missing_cost_filters[_]
} {
    msg = deny_missing_forecasting[_]
} {
    msg = deny_high_forecast_threshold[_]
} {
    msg = deny_excluded_services[_]
}
