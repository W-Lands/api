from __future__ import annotations

from enum import Enum
from typing import Literal, Annotated

from pydantic import BaseModel, Field, OnErrorOmit, ConfigDict, PlainSerializer
from pydantic_core.core_schema import SerializationInfo
from tortoise import Model, fields

from wlands import models


# https://github.com/FlintMC/FlintMC/blob/09e47975b04bc26198835d55964369e12a7ee882/render/gui/src/main/java/net/flintmc/render/gui/input/Key.java#L7
class Keybind(Enum):
    NOT_BOUND = -1, "key.keyboard.unknown"
    MOUSE_BUTTON_LEFT = -100, "key.mouse.left"
    MOUSE_BUTTON_RIGHT = -99, "key.mouse.right"
    MOUSE_BUTTON_MIDDLE = -98, "key.mouse.middle"
    MOUSE_BUTTON_3 = None, "key.mouse.3"
    MOUSE_BUTTON_4 = -97, "key.mouse.4"
    MOUSE_BUTTON_5 = -96, "key.mouse.5"
    MOUSE_BUTTON_6 = -95, "key.mouse.6"
    MOUSE_BUTTON_7 = -94, "key.mouse.7"
    MOUSE_BUTTON_8 = -93, "key.mouse.8"
    KEYBOARD_0 = 11, "key.keyboard.0"
    KEYBOARD_1 = 2, "key.keyboard.1"
    KEYBOARD_2 = 3, "key.keyboard.2"
    KEYBOARD_3 = 4, "key.keyboard.3"
    KEYBOARD_4 = 5, "key.keyboard.4"
    KEYBOARD_5 = 6, "key.keyboard.5"
    KEYBOARD_6 = 7, "key.keyboard.6"
    KEYBOARD_7 = 8, "key.keyboard.7"
    KEYBOARD_8 = 9, "key.keyboard.8"
    KEYBOARD_9 = 10, "key.keyboard.9"
    KEYBOARD_A = 30, "key.keyboard.a"
    KEYBOARD_B = 48, "key.keyboard.b"
    KEYBOARD_C = 46, "key.keyboard.c"
    KEYBOARD_D = 32, "key.keyboard.d"
    KEYBOARD_E = 18, "key.keyboard.e"
    KEYBOARD_F = 33, "key.keyboard.f"
    KEYBOARD_G = 34, "key.keyboard.g"
    KEYBOARD_H = 35, "key.keyboard.h"
    KEYBOARD_I = 23, "key.keyboard.i"
    KEYBOARD_J = 36, "key.keyboard.j"
    KEYBOARD_K = 37, "key.keyboard.k"
    KEYBOARD_L = 38, "key.keyboard.l"
    KEYBOARD_M = 50, "key.keyboard.m"
    KEYBOARD_N = 49, "key.keyboard.n"
    KEYBOARD_O = 24, "key.keyboard.o"
    KEYBOARD_P = 25, "key.keyboard.p"
    KEYBOARD_Q = 16, "key.keyboard.q"
    KEYBOARD_R = 19, "key.keyboard.r"
    KEYBOARD_S = 31, "key.keyboard.s"
    KEYBOARD_T = 20, "key.keyboard.t"
    KEYBOARD_U = 22, "key.keyboard.u"
    KEYBOARD_V = 47, "key.keyboard.v"
    KEYBOARD_W = 17, "key.keyboard.w"
    KEYBOARD_X = 45, "key.keyboard.x"
    KEYBOARD_Y = 21, "key.keyboard.y"
    KEYBOARD_Z = 44, "key.keyboard.z"
    KEYBOARD_F1 = 59, "key.keyboard.f1"
    KEYBOARD_F2 = 60, "key.keyboard.f2"
    KEYBOARD_F3 = 61, "key.keyboard.f3"
    KEYBOARD_F4 = 62, "key.keyboard.f4"
    KEYBOARD_F5 = 63, "key.keyboard.f5"
    KEYBOARD_F6 = 64, "key.keyboard.f6"
    KEYBOARD_F7 = 65, "key.keyboard.f7"
    KEYBOARD_F8 = 66, "key.keyboard.f8"
    KEYBOARD_F9 = 67, "key.keyboard.f9"
    KEYBOARD_F10 = 68, "key.keyboard.f10"
    KEYBOARD_F11 = 87, "key.keyboard.f11"
    KEYBOARD_F12 = 88, "key.keyboard.f12"
    KEYBOARD_F13 = 100, "key.keyboard.f13"
    KEYBOARD_F14 = 101, "key.keyboard.f14"
    KEYBOARD_F15 = 102, "key.keyboard.f15"
    KEYBOARD_F16 = 103, "key.keyboard.f16"
    KEYBOARD_F17 = 104, "key.keyboard.f17"
    KEYBOARD_F18 = 105, "key.keyboard.f18"
    KEYBOARD_F19 = 113, "key.keyboard.f19"
    KEYBOARD_F20 = None, "key.keyboard.f20"
    KEYBOARD_F21 = None, "key.keyboard.f21"
    KEYBOARD_F22 = None, "key.keyboard.f22"
    KEYBOARD_F23 = None, "key.keyboard.f23"
    KEYBOARD_F24 = None, "key.keyboard.f24"
    KEYBOARD_F25 = None, "key.keyboard.f25"
    KEYBOARD_NUMLOCK = 69, "key.keyboard.num.lock"
    KEYBOARD_KEYPAD_0 = 82, "key.keyboard.keypad.0"
    KEYBOARD_KEYPAD_1 = 79, "key.keyboard.keypad.1"
    KEYBOARD_KEYPAD_2 = 80, "key.keyboard.keypad.2"
    KEYBOARD_KEYPAD_3 = 81, "key.keyboard.keypad.3"
    KEYBOARD_KEYPAD_4 = 75, "key.keyboard.keypad.4"
    KEYBOARD_KEYPAD_5 = 76, "key.keyboard.keypad.5"
    KEYBOARD_KEYPAD_6 = 77, "key.keyboard.keypad.6"
    KEYBOARD_KEYPAD_7 = 71, "key.keyboard.keypad.7"
    KEYBOARD_KEYPAD_8 = 72, "key.keyboard.keypad.8"
    KEYBOARD_KEYPAD_9 = 73, "key.keyboard.keypad.9"
    KEYBOARD_KEYPAD_ADD = 78, "key.keyboard.keypad.add"
    KEYBOARD_KEYPAD_DECIMAL = 83, "key.keyboard.keypad.decimal"
    KEYBOARD_KEYPAD_ENTER = 156, "key.keyboard.keypad.enter"
    KEYBOARD_KEYPAD_EQUAL = 141, "key.keyboard.keypad.equal"
    KEYBOARD_KEYPAD_MULTIPLY = 55, "key.keyboard.keypad.multiply"
    KEYBOARD_KEYPAD_DIVIDE = 181, "key.keyboard.keypad.divide"
    KEYBOARD_KEYPAD_SUBTRACT = 74, "key.keyboard.keypad.subtract"
    KEYBOARD_ARROW_DOWN = 208, "key.keyboard.down"
    KEYBOARD_ARROW_LEFT = 203, "key.keyboard.left"
    KEYBOARD_ARROW_RIGHT = 205, "key.keyboard.right"
    KEYBOARD_ARROW_UP = 200, "key.keyboard.up"
    KEYBOARD_APOSTROPHE = 40, "key.keyboard.apostrophe"
    KEYBOARD_BACKSLASH = 43, "key.keyboard.backslash"
    KEYBOARD_COMMA = 51, "key.keyboard.comma"
    KEYBOARD_EQUAL = 13, "key.keyboard.equal"
    KEYBOARD_GRAVE_ACCENT = 41, "key.keyboard.grave.accent"
    KEYBOARD_LEFT_BRACKET = 26, "key.keyboard.left.bracket"
    KEYBOARD_MINUS = 12, "key.keyboard.minus"
    KEYBOARD_PERIOD = 52, "key.keyboard.period"
    KEYBOARD_RIGHT_BRACKET = 27, "key.keyboard.right.bracket"
    KEYBOARD_SEMICOLON = 39, "key.keyboard.semicolon"
    KEYBOARD_SLASH = 53, "key.keyboard.slash"
    KEYBOARD_SPACE = 57, "key.keyboard.space"
    KEYBOARD_TAB = 15, "key.keyboard.tab"
    KEYBOARD_LEFT_ALT = 56, "key.keyboard.left.alt"
    KEYBOARD_LEFT_CONTROL = 29, "key.keyboard.left.control"
    KEYBOARD_LEFT_SHIFT = 42, "key.keyboard.left.shift"
    KEYBOARD_LEFT_WIN = 219, "key.keyboard.left.win"
    KEYBOARD_RIGHT_ALT = 184, "key.keyboard.right.alt"
    KEYBOARD_RIGHT_CONTROL = 157, "key.keyboard.right.control"
    KEYBOARD_RIGHT_SHIFT = 54, "key.keyboard.right.shift"
    KEYBOARD_RIGHT_WIN = 220, "key.keyboard.right.win"
    KEYBOARD_ENTER = 28, "key.keyboard.enter"
    KEYBOARD_ESCAPE = 1, "key.keyboard.escape"
    KEYBOARD_BACKSPACE = 14, "key.keyboard.backspace"
    KEYBOARD_DELETE = 211, "key.keyboard.delete"
    KEYBOARD_END = 207, "key.keyboard.end"
    KEYBOARD_HOME = 199, "key.keyboard.home"
    KEYBOARD_INSERT = 210, "key.keyboard.insert"
    KEYBOARD_PAGE_DOWN = 209, "key.keyboard.page.down"
    KEYBOARD_PAGE_UP = 201, "key.keyboard.page.up"
    KEYBOARD_CAPS_LOCK = 58, "key.keyboard.caps.lock"
    KEYBOARD_PAUSE = None, "key.keyboard.pause"
    KEYBOARD_SCROLL_LOCK = 70, "key.keyboard.scroll.lock"
    KEYBOARD_MENU = None, "key.keyboard.menu"
    PRINT_SCREEN = None, "key.keyboard.print.screen"
    WORLD_1 = None, "key.keyboard.world.1"
    WORLD_2 = None, "key.keyboard.world.2"

    _by_any_value: dict[int | str, Keybind]

    def __new__(cls, old_val: int | None, new_val: str) -> Keybind:
        if not hasattr(cls, "_by_any_value"):
            cls._by_any_value = {}
        obj = object.__new__(cls)
        obj._value_ = (old_val, new_val)
        cls._by_any_value[new_val] = obj
        if old_val is not None:
            cls._by_any_value[old_val] = obj
        return obj

    @property
    def old(self) -> int | None:
        return self._value_[0]

    @property
    def new(self) -> str:
        return self._value_[1]

    @classmethod
    def _missing_(cls, value: int | str) -> Keybind | None:
        return cls._by_any_value.get(value)


class OptionsTxtSerializationContext(BaseModel):
    keybinds_format: Literal["old", "new"]


def _keybinds_serializer(value: Keybind | None, info: SerializationInfo) -> int | str | None:
    if value is None:
        return None

    ctx = info.context
    if ctx is None or not isinstance(ctx, OptionsTxtSerializationContext):
        return value.new

    if ctx.keybinds_format == "old":
        return value.old

    return value.new


OptBool = OnErrorOmit[bool | None]
OptFloat = OnErrorOmit[float | None]
OptInt = OnErrorOmit[int | None]
OptStr = OnErrorOmit[str | None]
OptKeybind = OnErrorOmit[Annotated[Keybind | None, PlainSerializer(_keybinds_serializer)]]


class OptionsTxt(BaseModel):
    model_config = ConfigDict(
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    auto_jump: OptBool = Field(None, alias="autoJump")
    auto_suggestions: OptBool = Field(None, alias="autoSuggestions")
    chat_colors: OptBool = Field(None, alias="chatColors")
    chat_links: OptBool = Field(None, alias="chatLinks")
    chat_links_prompt: OptBool = Field(None, alias="chatLinksPrompt")
    enable_vsync: OptBool = Field(None, alias="enableVsync")
    entity_shadows: OptBool = Field(None, alias="entityShadows")
    force_unicode_font: OptBool = Field(None, alias="forceUnicodeFont")
    ignore_os_scroll: OptBool = Field(None, alias="discrete_mouse_scroll")
    invert_mouse_y: OptBool = Field(None, alias="invertYMouse")
    realms_notifications: OptBool = Field(None, alias="realmsNotifications")
    reduced_debug_info: OptBool = Field(None, alias="reducedDebugInfo")
    show_subtitles: OptBool = Field(None, alias="showSubtitles")
    directional_audio: OptBool = Field(None, alias="directionalAudio")
    touchscreen: OptBool = Field(None, alias="touchscreen")
    fullscreen: OptBool = Field(None, alias="fullscreen")
    bob_view: OptBool = Field(None, alias="bobView")
    toggle_crouch: OptBool = Field(None, alias="toggleCrouch")
    toggle_sprint: OptBool = Field(None, alias="toggleSprint")
    dark_loading_background: OptBool = Field(None, alias="darkMojangStudiosBackground")
    hide_lightning_flashes: OptBool = Field(None, alias="hideLightningFlashes")
    mouse_sensitivity: OptFloat = Field(None, alias="mouseSensitivity", le=1.0, ge=0.0)
    fov: OptFloat = Field(None, alias="fov", le=1.0, ge=-1.0)
    screen_effect_scale: OptFloat = Field(None, alias="screenEffectScale", le=1.0, ge=0.0)
    fov_effect_scale: OptFloat = Field(None, alias="fovEffectScale", le=1.0, ge=0.0)
    darkness_effect_scale: OptFloat = Field(None, alias="darknessEffectScale", le=1.0, ge=0.0)
    brightness: OptFloat = Field(None, alias="gamma", le=1.0, ge=0.0)
    render_distance: OptInt = Field(None, alias="renderDistance", le=32, ge=2)
    simulation_distance: OptInt = Field(None, alias="simulationDistance", le=32, ge=5)
    entity_distance_scaling: OptFloat = Field(None, alias="entityDistanceScaling", le=5.0, ge=0.5)
    gui_scale: OptInt = Field(None, alias="guiScale", le=8, ge=0)
    particles: OptInt = Field(None, alias="particles", le=2, ge=0)
    max_fps: OptInt = Field(None, alias="maxFps", le=260, ge=10)
    graphics_mode: OptInt = Field(None, alias="graphicsMode", le=2, ge=0)
    smooth_lighting: OptBool = Field(None, alias="ao")
    chunk_updates: OptInt = Field(None, alias="prioritizeChunkUpdates", le=2, ge=0)
    biome_blend_radius: OptInt = Field(None, alias="biomeBlendRadius", le=7, ge=0)
    render_clouds: OnErrorOmit[Literal["\"true\"", "\"false\"", "\"fast\""] | None] = Field(None, alias="renderClouds")
    last_server: OptStr = Field(None, alias="lastServer", max_length=64)
    lang: OptStr = Field(None, alias="lang", max_length=16)
    chat_visibility: OptInt = Field(None, alias="chatVisibility", le=2, ge=0)
    chat_opacity: OptFloat = Field(None, alias="chatOpacity", le=1.0, ge=0.0)
    chat_line_spacing: OptFloat = Field(None, alias="chatLineSpacing", le=1.0, ge=0.0)
    text_background_opacity: OptFloat = Field(None, alias="textBackgroundOpacity", le=1.0, ge=0.0)
    advanced_item_tooltips: OptBool = Field(None, alias="advancedItemTooltips")
    pause_on_lost_focus: OptBool = Field(None, alias="pauseOnLostFocus")
    chat_height_focused: OptFloat = Field(None, alias="chatHeightFocused", le=1.0, ge=0.0)
    chat_delay: OptFloat = Field(None, alias="chatDelay", le=6.0, ge=0.0)
    chat_height_unnfocused: OptFloat = Field(None, alias="chatHeightUnfocused", le=1.0, ge=0.0)
    chat_scale: OptFloat = Field(None, alias="chatScale", le=1.0, ge=0.0)
    chat_width: OptFloat = Field(None, alias="chatWidth", le=1.0, ge=0.0)
    mipmap_levels: OptInt = Field(None, alias="mipmapLevels", le=4, ge=0)
    main_hand: OnErrorOmit[Literal["\"left\"", "\"right\""] | None] = Field(None, alias="mainHand")
    attack_indicator: OptInt = Field(None, alias="attackIndicator", le=2, ge=0)
    narrator: OptInt = Field(None, alias="narrator", le=3, ge=0)
    mouse_wheel_sensitivity: OptFloat = Field(None, alias="mouseWheelSensitivity", le=10.0, ge=1.0)
    raw_mouse_input: OptBool = Field(None, alias="rawMouseInput")
    allow_server_listing: OptBool = Field(None, alias="allowServerListing")
    keybind_attack: OptKeybind = Field(None, alias="key_key.attack")
    keybind_use: OptKeybind = Field(None, alias="key_key.use")
    keybind_forward: OptKeybind = Field(None, alias="key_key.forward")
    keybind_left: OptKeybind = Field(None, alias="key_key.left")
    keybind_back: OptKeybind = Field(None, alias="key_key.back")
    keybind_right: OptKeybind = Field(None, alias="key_key.right")
    keybind_jump: OptKeybind = Field(None, alias="key_key.jump")
    keybind_sneak: OptKeybind = Field(None, alias="key_key.sneak")
    keybind_sprint: OptKeybind = Field(None, alias="key_key.sprint")
    keybind_drop: OptKeybind = Field(None, alias="key_key.drop")
    keybind_inventory: OptKeybind = Field(None, alias="key_key.inventory")
    keybind_chat: OptKeybind = Field(None, alias="key_key.chat")
    keybind_player_list: OptKeybind = Field(None, alias="key_key.playerlist")
    keybind_pick_item: OptKeybind = Field(None, alias="key_key.pickItem")
    keybind_command: OptKeybind = Field(None, alias="key_key.command")
    keybind_social_interactions: OptKeybind = Field(None, alias="key_key.socialInteractions")
    keybind_screenshot: OptKeybind = Field(None, alias="key_key.screenshot")
    keybind_toggle_perspective: OptKeybind = Field(None, alias="key_key.togglePerspective")
    keybind_smooth_camera: OptKeybind = Field(None, alias="key_key.smoothCamera")
    keybind_fullscreen: OptKeybind = Field(None, alias="key_key.fullscreen")
    keybind_spectator_outlines: OptKeybind = Field(None, alias="key_key.spectatorOutlines")
    keybind_swap_offhand: OptKeybind = Field(None, alias="key_key.swapOffhand")
    keybind_save_toolbar: OptKeybind = Field(None, alias="key_key.saveToolbarActivator")
    keybind_load_toolbar: OptKeybind = Field(None, alias="key_key.loadToolbarActivator")
    keybind_advancements: OptKeybind = Field(None, alias="key_key.advancements")
    keybind_hotbar_1: OptKeybind = Field(None, alias="key_key.hotbar.1")
    keybind_hotbar_2: OptKeybind = Field(None, alias="key_key.hotbar.2")
    keybind_hotbar_3: OptKeybind = Field(None, alias="key_key.hotbar.3")
    keybind_hotbar_4: OptKeybind = Field(None, alias="key_key.hotbar.4")
    keybind_hotbar_5: OptKeybind = Field(None, alias="key_key.hotbar.5")
    keybind_hotbar_6: OptKeybind = Field(None, alias="key_key.hotbar.6")
    keybind_hotbar_7: OptKeybind = Field(None, alias="key_key.hotbar.7")
    keybind_hotbar_8: OptKeybind = Field(None, alias="key_key.hotbar.8")
    keybind_hotbar_9: OptKeybind = Field(None, alias="key_key.hotbar.9")
    sound_master: OptFloat = Field(None, alias="soundCategory_master", le=1.0, ge=0.0)
    sound_music: OptFloat = Field(None, alias="soundCategory_music", le=1.0, ge=0.0)
    sound_record: OptFloat = Field(None, alias="soundCategory_record", le=1.0, ge=0.0)
    sound_weather: OptFloat = Field(None, alias="soundCategory_weather", le=1.0, ge=0.0)
    sound_block: OptFloat = Field(None, alias="soundCategory_block", le=1.0, ge=0.0)
    sound_hostile: OptFloat = Field(None, alias="soundCategory_hostile", le=1.0, ge=0.0)
    sound_neutral: OptFloat = Field(None, alias="soundCategory_neutral", le=1.0, ge=0.0)
    sound_player: OptFloat = Field(None, alias="soundCategory_player", le=1.0, ge=0.0)
    sound_ambient: OptFloat = Field(None, alias="soundCategory_ambient", le=1.0, ge=0.0)
    sound_voice: OptFloat = Field(None, alias="soundCategory_voice", le=1.0, ge=0.0)
    skin_cape: OptBool = Field(None, alias="modelPart_cape")
    skin_jacket: OptBool = Field(None, alias="modelPart_jacket")
    skin_left_sleeve: OptBool = Field(None, alias="modelPart_left_sleeve")
    skin_right_sleeve: OptBool = Field(None, alias="modelPart_right_sleeve")
    skin_left_pants_leg: OptBool = Field(None, alias="modelPart_left_pants_leg")
    skin_right_pants_leg: OptBool = Field(None, alias="modelPart_right_pants_leg")
    skin_hat: OptBool = Field(None, alias="modelPart_hat")


class OptionsSync(Model):
    id: int = fields.BigIntField(primary_key=True)
    user: models.User = fields.ForeignKeyField("models.User")
    name: str = fields.CharField(max_length=64)
    settings: dict = fields.JSONField(default={})

    class Meta:
        unique_together = (
            ("user", "name"),
        )