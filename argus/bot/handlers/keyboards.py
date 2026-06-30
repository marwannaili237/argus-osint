"""Custom keyboard builders for Telegram bot."""
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton


def build_main_menu_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔍 Scan Target"), KeyboardButton(text="📂 Investigations")],
            [KeyboardButton(text="⚙️ Settings"), KeyboardButton(text="📊 My Stats")],
            [KeyboardButton(text="❓ Help")],
        ],
        resize_keyboard=True,
    )


def build_settings_keyboard(current_lang: str = "en") -> InlineKeyboardMarkup:
    langs = [("English", "en"), ("Francais", "fr"), ("Arabic", "ar"), ("Espanol", "es")]
    buttons = []
    for name, code in langs:
        prefix = "✅ " if code == current_lang else ""
        buttons.append([InlineKeyboardButton(text=f"{prefix}{name}", callback_data=f"lang:{code}")])
    buttons.append([InlineKeyboardButton(text="🔙 Back", callback_data="settings:back")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def build_investigation_keyboard(inv_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔍 Scan All Targets", callback_data=f"inv:scan:{inv_id}")],
            [InlineKeyboardButton(text="📄 Export PDF", callback_data=f"inv:export_pdf:{inv_id}")],
            [InlineKeyboardButton(text="📊 Export CSV", callback_data=f"inv:export_csv:{inv_id}")],
            [InlineKeyboardButton(text="🗑 Close", callback_data=f"inv:close:{inv_id}")],
        ]
    )


def build_plugin_results_keyboard(target_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Rescan", callback_data=f"target:rescan:{target_id}")],
            [InlineKeyboardButton(text="📄 Export", callback_data=f"target:export:{target_id}")],
            [InlineKeyboardButton(text="🔗 Add to Investigation", callback_data=f"target:add_inv:{target_id}")],
        ]
    )
