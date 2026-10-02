const result = document.querySelector("#result");

for (const form of document.querySelectorAll("form[data-endpoint]")) {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const payload = Object.fromEntries(new FormData(form).entries());
        const response = await fetch(form.dataset.endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        result.textContent = JSON.stringify(data, null, 2);
        if (data.demo_magic_link) {
            const link = document.createElement("a");
            link.href = data.demo_magic_link;
            link.textContent = "Открыть одноразовую ссылку";
            result.after(link);
        }
    });
}

