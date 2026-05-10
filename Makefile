publish:
	uv run python -m build
	uv run twine upload dist/*

release:
	gh release create $(TAG) --generate-notes
