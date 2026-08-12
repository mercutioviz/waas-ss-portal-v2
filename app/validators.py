"""Lightweight input validation for AJAX endpoints (no external dependencies)."""


class ValidationError(Exception):
    """Raised when input data fails validation."""

    def __init__(self, errors):
        self.errors = errors  # dict of field -> error message
        super().__init__(str(errors))


class FieldValidator:
    """Validates and coerces a single field value."""

    def __init__(self, field_type='string', required=False, min_val=None, max_val=None,
                 max_length=None, allowed=None, default=None):
        self.field_type = field_type  # 'string', 'int', 'bool'
        self.required = required
        self.min_val = min_val
        self.max_val = max_val
        self.max_length = max_length
        self.allowed = allowed  # list of allowed values
        self.default = default

    def validate(self, value, field_name='field'):
        """Validate and coerce a value. Returns the coerced value."""
        if value is None:
            if self.required:
                raise ValueError(f'{field_name} is required')
            return self.default

        # Type coercion
        if self.field_type == 'int':
            try:
                value = int(value)
            except (ValueError, TypeError):
                raise ValueError(f'{field_name} must be an integer')

            if self.min_val is not None and value < self.min_val:
                raise ValueError(f'{field_name} must be at least {self.min_val}')
            if self.max_val is not None and value > self.max_val:
                raise ValueError(f'{field_name} must be at most {self.max_val}')

        elif self.field_type == 'bool':
            if isinstance(value, bool):
                pass
            elif isinstance(value, str):
                value = value.lower() in ('true', '1', 'yes', 'on')
            else:
                value = bool(value)

        elif self.field_type == 'string':
            value = str(value).strip()
            if self.max_length and len(value) > self.max_length:
                raise ValueError(f'{field_name} must be at most {self.max_length} characters')

        # Allowed values check
        if self.allowed is not None and value not in self.allowed:
            raise ValueError(f'{field_name} must be one of: {", ".join(str(a) for a in self.allowed)}')

        return value


def validate_data(data, schema):
    """Validate a dict against a schema.

    Args:
        data: dict of field_name -> value
        schema: dict of field_name -> FieldValidator

    Returns:
        dict of validated/coerced values (only fields present in schema)

    Raises:
        ValidationError with dict of field -> error message
    """
    errors = {}
    result = {}

    for field_name, validator in schema.items():
        value = data.get(field_name)
        try:
            coerced = validator.validate(value, field_name)
            if coerced is not None:
                result[field_name] = coerced
        except ValueError as e:
            errors[field_name] = str(e)

    if errors:
        raise ValidationError(errors)

    return result
