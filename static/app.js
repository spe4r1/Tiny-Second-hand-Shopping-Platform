document.addEventListener("DOMContentLoaded", () => {
  for (const form of document.querySelectorAll("form")) {
    form.addEventListener("submit", () => {
      const button = form.querySelector("button[type='submit'], button:not([type])");
      if (button && !button.disabled) {
        button.dataset.originalText = button.textContent;
        button.textContent = "처리 중";
      }
    });
  }
});
