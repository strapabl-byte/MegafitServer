// test_groq.js
const dotenv = require('dotenv');
dotenv.config();

async function testGroq() {
    const apiKey = process.env.GROQ_API_KEY;
    console.log("Using API Key:", apiKey ? (apiKey.slice(0, 10) + "...") : "MISSING");

    if (!apiKey) {
        console.error("❌ GROQ_API_KEY is not defined in .env");
        return;
    }

    try {
        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                messages: [
                    { role: "user", content: "Hello, are you working?" }
                ],
                model: "llama-3.3-70b-versatile",
                max_tokens: 50
            })
        });

        const data = await response.json();
        if (response.ok) {
            console.log("✅ Groq API is working!");
            console.log("Response:", data.choices[0].message.content);
        } else {
            console.error("❌ Groq API Error:", response.status, data);
        }
    } catch (error) {
        console.error("❌ Network Error:", error.message);
    }
}

testGroq();
