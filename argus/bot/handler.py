"""Main Telegram bot handler using aiogram 3."""
import asyncio
import logging
from aiogram import Bot, Dispatcher, Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery

from argus.config import settings
from argus.plugins.classifier import classify_target
from argus.bot.i18n import t, SUPPORTED_LANGUAGES
from argus.bot.handlers.progress import create_progress_bar, get_threat_emoji, format_scan_summary
from argus.bot.handlers.pagination import build_pagination_keyboard, handle_pagination_callback, get_page, set_page
from argus.bot.handlers.keyboards import build_main_menu_keyboard, build_settings_keyboard

logger = logging.getLogger(__name__)
router = Router()


def create_bot() -> tuple[Bot, Dispatcher]:
    bot = Bot(token=settings.BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    return bot, dp


@router.message(CommandStart())
async def cmd_start(message: Message):
    lang = "en"
    text = t("welcome", lang)
    await message.answer(text, reply_markup=build_main_menu_keyboard())


@router.message(Command("help"))
async def cmd_help(message: Message):
    lang = "en"
    await message.answer(t("help_text", lang))


@router.message(Command("language"))
async def cmd_language(message: Message):
    await message.answer("Select language:", reply_markup=build_settings_keyboard("en"))


@router.callback_query(F.data.startswith("lang:"))
async def callback_language(callback: CallbackQuery):
    lang_code = callback.data.split(":")[1]
    if lang_code in SUPPORTED_LANGUAGES:
        await callback.answer(t("language_changed", "en", lang=lang_code))
        await callback.message.edit_text(f"Language set to {lang_code}")
    else:
        await callback.answer("Invalid language.")


@router.message(Command("scan"))
async def cmd_scan(message: Message):
    if not message.text or len(message.text.split()) < 2:
        await message.answer(t("type_prompt", "en"))
        return
    target_value = message.text.split(maxsplit=1)[1].strip()
    target_type = classify_target(target_value)
    await message.answer(t("classification", "en", type=target_type))
    try:
        from argus.plugins.runner import run_all_for_target
        await message.answer(t("scanning", "en", target=target_value, current=0, total=1))
        results = await run_all_for_target(target_value, target_type)
        summary = format_scan_summary([{"plugin_name": r.plugin_name, "status": r.status, "execution_time": r.execution_time} for r in results])
        await message.answer(f"{t("results_header", "en", target=target_value)}

{summary}")
        await message.answer(t("scan_complete", "en", success=len([r for r in results if r.status == "success"]), failed=len([r for r in results if r.status != "success"])))
    except Exception as e:
        logger.exception("Scan error")
        await message.answer(t("error", "en", error=str(e)))


async def run_bot():
    bot, dp = create_bot()
    logger.info("Starting Telegram bot polling...")
    await dp.start_polling(bot)
