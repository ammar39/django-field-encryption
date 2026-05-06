publish:
	uv run python -m build
	uv run twine upload dist/*
