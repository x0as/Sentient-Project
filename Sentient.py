import google.generativeai as genai
from traffic_sender import send_traffic
from real_traffic import imitate_real_traffic

def main():
    api_key = input("Enter your Access Key: ").strip()
    genai.configure(api_key=api_key)

    available_models = [
        m for m in genai.list_models()
        if hasattr(m, "supported_generation_methods") and "generateContent" in m.supported_generation_methods
    ]
    preferred_model = None
    for m in available_models:
        if "gemini-1.5-flash" in m.name:
            preferred_model = m
            break
    if not preferred_model and available_models:
        preferred_model = available_models[0]
    if not preferred_model:
        print("No compatible generative models available for your API key.")
        return
    model_name = preferred_model.name
    model = genai.GenerativeModel(model_name)

    system_prompt = (
        "You are Sentient, an AI command-line assistant for cybersecurity and automation. "
        "Respond concisely and directly. Only ask questions if more information is required to execute a command. "
        "You can analyze files, scan for viruses, test websites for SQL vulnerabilities, "
        "and interact with modules to send traffic or fulfill commands."
    )

    print(f"Sentient AI CLI (using model: {model_name}) (type 'exit' to quit)")

    # Confirmation state
    pending_confirmation = None

    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            break

        # Handle confirmation for real traffic
        if pending_confirmation:
            if user_input.lower() == "y":
                url, count = pending_confirmation
                result = imitate_real_traffic(url, count)
                print("Sentient:", result)
                pending_confirmation = None
                continue
            elif user_input.lower() == "n":
                print("Sentient: Cancelled.")
                pending_confirmation = None
                continue
            else:
                print("Sentient: Please reply with 'y' or 'n'.")
                continue

        # Handle traffic command: send traffic <url> <count>
        if user_input.startswith("send traffic"):
            parts = user_input.split()
            if len(parts) >= 3:
                url = parts[2]
                count = parts[3] if len(parts) > 3 else 1
                result = send_traffic(url, count)
                print("Sentient:", result)
                continue
            else:
                print("Sentient: Usage: send traffic <url> <count>")
                continue

        # Handle real traffic command: imitate traffic <url> <count> or immitate real traffic <url> <count>
        if (
            user_input.startswith("imitate traffic")
            or user_input.startswith("immitate real traffic")
        ):
            parts = user_input.split()
            # Support both command styles
            if user_input.startswith("imitate traffic"):
                url = parts[2]
                count = parts[3] if len(parts) > 3 else 1
            else:  # immitate real traffic
                url = parts[3]
                count = parts[4] if len(parts) > 4 else 1
            print(f"Sentient: Simulating {count} real browser visits to {url}. This may take time and impact the target server. Proceed? (y/n)")
            pending_confirmation = (url, count)
            continue

        prompt = f"{system_prompt}\nUser: {user_input}"
        response = model.generate_content(prompt)
        print("Sentient:", response.text.strip())

if __name__ == "__main__":
    main()