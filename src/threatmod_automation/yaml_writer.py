from __future__ import annotations


def dump_yaml(data: object, indent: int = 0) -> str:
    if isinstance(data, dict):
        lines: list[str] = []
        for key, value in data.items():
            if _is_scalar(value):
                lines.append(f"{' ' * indent}{key}: {_render_scalar(value)}")
            elif isinstance(value, list) and not value:
                lines.append(f"{' ' * indent}{key}: []")
            elif isinstance(value, dict) and not value:
                lines.append(f"{' ' * indent}{key}: {{}}")
            else:
                lines.append(f"{' ' * indent}{key}:")
                lines.append(dump_yaml(value, indent + 2))
        return "\n".join(lines)
    if isinstance(data, list):
        if not data:
            return f"{' ' * indent}[]"
        lines = []
        for item in data:
            if _is_scalar(item):
                lines.append(f"{' ' * indent}- {_render_scalar(item)}")
            else:
                lines.append(f"{' ' * indent}-")
                lines.append(dump_yaml(item, indent + 2))
        return "\n".join(lines)
    return f"{' ' * indent}{_render_scalar(data)}"


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _render_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(char in text for char in [":", "#", "{", "}", "[", "]"]) or text.strip() != text:
        escaped = text.replace('"', '\\"')
        return f'"{escaped}"'
    return text
