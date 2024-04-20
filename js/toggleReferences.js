function toggleReferences(element) {{
	var references = element.nextElementSibling;
	if (references.style.display === "none") {{
		references.style.display = "block";
		element.innerText = "Hide References";
	}} else {{
		references.style.display = "none";
		element.innerText = "Show References";
	}}
}}