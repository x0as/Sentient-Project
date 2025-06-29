import requests

def check_username(username):
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Facebook": f"https://facebook.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Tumblr": f"https://{username}.tumblr.com/",
        "Flickr": f"https://www.flickr.com/people/{username}/",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "DeviantArt": f"https://{username}.deviantart.com/",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}/",
        "Keybase": f"https://keybase.io/{username}",
        "About.me": f"https://about.me/{username}",
        "ProductHunt": f"https://www.producthunt.com/@{username}",
        "500px": f"https://500px.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "VK": f"https://vk.com/{username}",
        "OK.ru": f"https://ok.ru/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
    }
    results = {}
    for name, url in platforms.items():
        try:
            resp = requests.get(url, timeout=5)
            results[name] = resp.status_code == 200
        except Exception:
            results[name] = False
    return results

# Example usage:
# print(check_username("jack"))