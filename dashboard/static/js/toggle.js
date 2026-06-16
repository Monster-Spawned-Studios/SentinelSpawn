// Password visibility toggles — tiny, no dependencies.
document.addEventListener("click", function (e) {
    var btn = e.target.closest(".toggle-pw");
    if (!btn) return;
    var input = document.getElementById(btn.getAttribute("data-target"));
    if (!input) return;
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
});
