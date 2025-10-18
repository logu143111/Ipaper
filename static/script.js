function toggleVisibility(id, element) {
  const input = document.getElementById(id);
  if (input.type === "password") {
    input.type = "text";
    element.textContent = "🙈";
  } else {
    input.type = "password";
    element.textContent = "👁️";
  }
}

function toggleVisibility(id, toggleElement) {
  const field = document.getElementById(id);
  if (field.type === "password") {
    field.type = "text";
    toggleElement.textContent = "Hide";
  } else {
    field.type = "password";
    toggleElement.textContent = "Show";
  }
}
