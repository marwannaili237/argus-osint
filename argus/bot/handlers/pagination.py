"""Pagination helpers for Telegram bot."""
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from collections import defaultdict


_pagination_state: dict[int, int] = defaultdict(int)


def build_pagination_keyboard(current_page: int, total_pages: int, callback_prefix: str = "page") -> InlineKeyboardMarkup:
    buttons = []
    nav_row = []
    if current_page > 1:
        nav_row.append(InlineKeyboardButton(text="⏮ First", callback_data=f"{callback_prefix}:first"))
        nav_row.append(InlineKeyboardButton(text="◀ Prev", callback_data=f"{callback_prefix}:prev"))
    if current_page < total_pages:
        nav_row.append(InlineKeyboardButton(text="Next ▶", callback_data=f"{callback_prefix}:next"))
        nav_row.append(InlineKeyboardButton(text="Last ⏭", callback_data=f"{callback_prefix}:last"))
    if nav_row:
        buttons.append(nav_row)
    buttons.append([InlineKeyboardButton(text=f"Page {current_page}/{total_pages}", callback_data="noop")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def set_page(chat_id: int, page: int):
    _pagination_state[chat_id] = page


def get_page(chat_id: int) -> int:
    return _pagination_state.get(chat_id, 1)


async def handle_pagination_callback(callback_data: str, current: int, total: int) -> int | None:
    parts = callback_data.split(":")
    if len(parts) < 2:
        return None
    action = parts[1]
    if action == "first":
        return 1
    elif action == "prev":
        return max(1, current - 1)
    elif action == "next":
        return min(total, current + 1)
    elif action == "last":
        return total
    return None
