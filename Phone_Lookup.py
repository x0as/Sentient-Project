import phonenumbers
from phonenumbers import geocoder, carrier, timezone

def phone_lookup_cli(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        if phonenumbers.is_valid_number(parsed_number):
            status = "Valid"
        else:
            status = "Invalid"

        if phone_number.startswith("+"):
            country_code = "+" + phone_number[1:3]
        else:
            country_code = "None"

        try:
            operator = carrier.name_for_number(parsed_number, "en")
        except Exception:
            operator = "None"

        try:
            type_number = "Mobile" if phonenumbers.number_type(parsed_number) == phonenumbers.PhoneNumberType.MOBILE else "Fixed"
        except Exception:
            type_number = "None"

        try:
            timezones = timezone.time_zones_for_number(parsed_number)
            timezone_info = timezones[0] if timezones else "None"
        except Exception:
            timezone_info = "None"

        try:
            country = phonenumbers.region_code_for_number(parsed_number)
        except Exception:
            country = "None"

        try:
            region = geocoder.description_for_number(parsed_number, "en")
        except Exception:
            region = "None"

        try:
            formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
        except Exception:
            formatted_number = "None"

        result = {
            "Phone": phone_number,
            "Formatted": formatted_number,
            "Status": status,
            "Country Code": country_code,
            "Country": country,
            "Region": region,
            "Timezone": timezone_info,
            "Operator": operator,
            "Type Number": type_number,
        }
        return result
    except Exception:
        return {"Error": "Invalid Format!"}

if __name__ == "__main__":
    phone = input("Phone Number -> ")
    info = phone_lookup_cli(phone)
    print("\n[~] Information Recovery..\n")
    for k, v in info.items():
        print(f"[+] {k:<12}: {v}")