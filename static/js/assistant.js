const chat = document.querySelector("#assistant-chat");
const chatForm = document.querySelector("#assistant-form");
const questionInput = document.querySelector("#assistant-question");
const messagesElement = document.querySelector("#assistant-messages");
const clearButton = document.querySelector("#assistant-clear");
const statusElement = document.querySelector("#assistant-status");
const conversation = [];

function appendMessage(role, text) {
    const message = document.createElement("article");
    message.className = `chat-message ${role === "user" ? "user-message" : "assistant-message"}`;
    const label = document.createElement("strong");
    label.textContent = role === "user" ? "You" : "Security Assistant";
    const body = document.createElement("p");
    body.textContent = text;
    message.append(label, body);
    messagesElement.append(message);
    messagesElement.scrollTop = messagesElement.scrollHeight;
}

function resetMessages() {
    messagesElement.replaceChildren();
    appendMessage(
        "assistant",
        "I can explain recorded observations and suggest defensive verification steps. What would you like to understand?",
    );
}

if (chatForm && chat && questionInput && messagesElement) {
    chatForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const question = questionInput.value.trim();
        if (!question) return;

        const submitButton = chatForm.querySelector("button[type='submit']");
        submitButton.disabled = true;
        questionInput.disabled = true;
        statusElement.textContent = "Preparing an explanation…";
        try {
            const requestBody = {
                question,
                scan_id: chat.dataset.scanId || undefined,
                finding_index: chat.dataset.findingIndex === ""
                    ? undefined
                    : Number(chat.dataset.findingIndex),
                history: conversation.slice(-8),
            };
            const response = await fetch(chat.dataset.apiUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(requestBody),
            });
            const payload = await response.json();
            if (!response.ok) {
                throw new Error(payload.error || "The assistant request failed.");
            }

            appendMessage("user", question);
            appendMessage("assistant", payload.message);
            if (payload.configured) {
                conversation.push(
                    { role: "user", content: question },
                    { role: "assistant", content: payload.message },
                );
            }
            questionInput.value = "";
            statusElement.textContent = "";
        } catch (error) {
            statusElement.textContent = error.message;
        } finally {
            submitButton.disabled = false;
            questionInput.disabled = false;
            questionInput.focus();
        }
    });

    document.querySelectorAll(".suggested-questions button").forEach((button) => {
        button.addEventListener("click", () => {
            questionInput.value = button.textContent.trim();
            questionInput.focus();
        });
    });

    clearButton.addEventListener("click", () => {
        conversation.length = 0;
        resetMessages();
        statusElement.textContent = "Conversation cleared.";
    });
}
