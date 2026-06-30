"""Inline query handler for Telegram bot."""
import logging
from aiogram import Router
from aiogram.types import InlineQuery, InlineQueryResultArticle, InputTextMessageContent

logger = logging.getLogger(__name__)
router = Router()


@router.inline_query()
async def handle_inline_query(inline_query: InlineQuery):
    query = inline_query.query.strip()
    if not query:
        await inline_query.answer([])
        return
    items = []
    suggestions = [
        f"Scan: {query}",
        f"DNS lookup: {query}",
        f"Whois: {query}",
        f"Reverse IP: {query}",
    ]
    for i, text in enumerate(suggestions):
        items.append(
            InlineQueryResultArticle(
                id=str(i),
                title=text,
                description=f"Click to {text.split(": ")[0].lower()}",
                input_message_content=InputTextMessageContent(message_text=f"/scan {query}"),
            )
        )
    await inline_query.answer(items, cache_time=60)
