import html

def format_badge_label(role: str) -> str:
    return role.strip().upper()

def render_user_profile_card(display_name: str, bio: str) -> str:
    return f"<div class='profile'><h2>{display_name}</h2><p>{bio}</p></div>"
