import os
import sys

def main():
    print("--- Rapg Injection Test ---")
    
    # The keys you configured in Rapg (e.g., DATABASE_URL)
    target_keys = ["DATABASE_URL", "API_KEY"]
    
    found = False
    for key in target_keys:
        val = os.environ.get(key)
        if val:
            print(f"✅  {key} is injected!")
            print(f"    Value: {val}")
            found = True
        else:
            print(f"❌  {key} is missing.")

    if not found:
        print("\nNo secrets found. Make sure you set the 'Env Key' field in Rapg.")
        sys.exit(1)
    else:
        print("\nSuccess! The process can read your secrets.")

if __name__ == "__main__":
    main()

