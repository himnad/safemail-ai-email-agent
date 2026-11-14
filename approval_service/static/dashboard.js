// SafeMail demo: update only the selected email card.
// No real email is sent from these demo actions.
document.addEventListener("submit", async (event) => {
    const form = event.target.closest("form[data-ajax='true']");
    if (!form) return;
    event.preventDefault();

    const card = form.closest("[data-email-id]");
    const button = event.submitter || form.querySelector("button[type='submit']");
    const originalText = button ? button.textContent.trim() : "Working...";
    // Capture the clicked button's name/value (APPROVED or REJECTED) before disabling it.
    const formData = new FormData(form);
    if (button && button.name) formData.set(button.name, button.value);
    if (button) {
        button.disabled = true;
        button.textContent = "Please wait...";
    }
    if (card) card.classList.add("busy");

    try {
        const response = await fetch(form.action, {
            method: "POST",
            credentials: "same-origin",
            body: formData,
            headers: {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        });
        const data = await response.json();
        if (!response.ok || !data.ok) throw new Error(data.message || "Request failed");

        if (data.type === "analysis" && card) {
            const a = data.analysis || {};
            const panel = card.querySelector(".analysis-result");
            if (panel) {
                panel.innerHTML = `
                    <h3>Gemini AI Analysis</h3>
                    <p><b>Analysis status:</b> ${safe(a.analysis_status)}</p>
                    <p><b>Classification:</b> <span class="badge">${safe(a.category)}</span></p>
                    <p><b>Reason:</b> ${safe(a.reason)}</p>
                    <p><b>Recommended action:</b> ${safe(a.recommended_action)}</p>
                    <p><b>Suggested reply:</b></p>
                    <textarea readonly>${safe(a.draft_reply)}</textarea>`;
            }
            const category = card.querySelector("[data-category]");
            if (category) category.textContent = a.category || "UNKNOWN";
            showNotice(card, "Gemini analysis completed.", false);
        } else if (data.type === "decision" && card) {
            const status = card.querySelector("[data-status]");
            if (status) {
                status.textContent = data.status;
                status.className = "status-pill " + String(data.status).toLowerCase();
            }
            card.querySelectorAll(".decision-button").forEach(b => b.disabled = true);
            showNotice(card, "Decision recorded in simulated demo state.", false);
        }
    } catch (error) {
        showNotice(card || document.body, error.message || "Something went wrong.", true);
    } finally {
        if (card) card.classList.remove("busy");
        if (button && form.action.includes("/analyze/")) {
            button.disabled = false;
            button.textContent = originalText;
        } else if (button && !button.closest("[data-email-id]")?.querySelector("[data-status]")?.textContent?.match(/^(APPROVED|REJECTED)$/)) {
            button.disabled = false;
            button.textContent = originalText;
        }
    }
});

function safe(value) {
    return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[ch]));
}

function showNotice(target, message, isError) {
    let notice = target.querySelector(".ajax-notice");
    if (!notice) {
        notice = document.createElement("p");
        notice.className = "ajax-notice notice";
        target.appendChild(notice);
    }
    notice.textContent = message;
    notice.style.color = isError ? "#b91c1c" : "#166534";
}
