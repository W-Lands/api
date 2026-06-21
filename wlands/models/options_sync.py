from enum import StrEnum
from typing import Literal, Annotated

from pydantic import BaseModel, Field, OnErrorOmit, ConfigDict
from tortoise import Model, fields

from wlands import models


class Keybind(StrEnum):
    NOT_BOUND = "key.keyboard.unknown"
    MOUSE_BUTTON_LEFT = "key.mouse.left"
    MOUSE_BUTTON_RIGHT = "key.mouse.right"
    MOUSE_BUTTON_MIDDLE = "key.mouse.middle"
    MOUSE_BUTTON_3 = "key.mouse.3"
    MOUSE_BUTTON_4 = "key.mouse.4"
    MOUSE_BUTTON_5 = "key.mouse.5"
    MOUSE_BUTTON_6 = "key.mouse.6"
    MOUSE_BUTTON_7 = "key.mouse.7"
    MOUSE_BUTTON_8 = "key.mouse.8"
    MOUSE_BUTTON_9 = "key.mouse.9"
    MOUSE_BUTTON_10 = "key.mouse.10"
    MOUSE_BUTTON_11 = "key.mouse.11"
    MOUSE_BUTTON_12 = "key.mouse.12"
    MOUSE_BUTTON_13 = "key.mouse.13"
    MOUSE_BUTTON_14 = "key.mouse.14"
    MOUSE_BUTTON_15 = "key.mouse.15"
    MOUSE_BUTTON_16 = "key.mouse.16"
    KEYBOARD_0 = "key.keyboard.0"
    KEYBOARD_1 = "key.keyboard.1"
    KEYBOARD_2 = "key.keyboard.2"
    KEYBOARD_3 = "key.keyboard.3"
    KEYBOARD_4 = "key.keyboard.4"
    KEYBOARD_5 = "key.keyboard.5"
    KEYBOARD_6 = "key.keyboard.6"
    KEYBOARD_7 = "key.keyboard.7"
    KEYBOARD_8 = "key.keyboard.8"
    KEYBOARD_9 = "key.keyboard.9"
    KEYBOARD_A = "key.keyboard.a"
    KEYBOARD_B = "key.keyboard.b"
    KEYBOARD_C = "key.keyboard.c"
    KEYBOARD_D = "key.keyboard.d"
    KEYBOARD_E = "key.keyboard.e"
    KEYBOARD_F = "key.keyboard.f"
    KEYBOARD_G = "key.keyboard.g"
    KEYBOARD_H = "key.keyboard.h"
    KEYBOARD_I = "key.keyboard.i"
    KEYBOARD_J = "key.keyboard.j"
    KEYBOARD_K = "key.keyboard.k"
    KEYBOARD_L = "key.keyboard.l"
    KEYBOARD_M = "key.keyboard.m"
    KEYBOARD_N = "key.keyboard.n"
    KEYBOARD_O = "key.keyboard.o"
    KEYBOARD_P = "key.keyboard.p"
    KEYBOARD_Q = "key.keyboard.q"
    KEYBOARD_R = "key.keyboard.r"
    KEYBOARD_S = "key.keyboard.s"
    KEYBOARD_T = "key.keyboard.t"
    KEYBOARD_U = "key.keyboard.u"
    KEYBOARD_V = "key.keyboard.v"
    KEYBOARD_W = "key.keyboard.w"
    KEYBOARD_X = "key.keyboard.x"
    KEYBOARD_Y = "key.keyboard.y"
    KEYBOARD_Z = "key.keyboard.z"
    KEYBOARD_F1 = "key.keyboard.f1"
    KEYBOARD_F2 = "key.keyboard.f2"
    KEYBOARD_F3 = "key.keyboard.f3"
    KEYBOARD_F4 = "key.keyboard.f4"
    KEYBOARD_F5 = "key.keyboard.f5"
    KEYBOARD_F6 = "key.keyboard.f6"
    KEYBOARD_F7 = "key.keyboard.f7"
    KEYBOARD_F8 = "key.keyboard.f8"
    KEYBOARD_F9 = "key.keyboard.f9"
    KEYBOARD_F10 = "key.keyboard.f10"
    KEYBOARD_F11 = "key.keyboard.f11"
    KEYBOARD_F12 = "key.keyboard.f12"
    KEYBOARD_F13 = "key.keyboard.f13"
    KEYBOARD_F14 = "key.keyboard.f14"
    KEYBOARD_F15 = "key.keyboard.f15"
    KEYBOARD_F16 = "key.keyboard.f16"
    KEYBOARD_F17 = "key.keyboard.f17"
    KEYBOARD_F18 = "key.keyboard.f18"
    KEYBOARD_F19 = "key.keyboard.f19"
    KEYBOARD_F20 = "key.keyboard.f20"
    KEYBOARD_F21 = "key.keyboard.f21"
    KEYBOARD_F22 = "key.keyboard.f22"
    KEYBOARD_F23 = "key.keyboard.f23"
    KEYBOARD_F24 = "key.keyboard.f24"
    KEYBOARD_F25 = "key.keyboard.f25"
    KEYBOARD_NUMLOCK = "key.keyboard.num.lock"
    KEYBOARD_KEYPAD_0 = "key.keyboard.keypad.0"
    KEYBOARD_KEYPAD_1 = "key.keyboard.keypad.1"
    KEYBOARD_KEYPAD_2 = "key.keyboard.keypad.2"
    KEYBOARD_KEYPAD_3 = "key.keyboard.keypad.3"
    KEYBOARD_KEYPAD_4 = "key.keyboard.keypad.4"
    KEYBOARD_KEYPAD_5 = "key.keyboard.keypad.5"
    KEYBOARD_KEYPAD_6 = "key.keyboard.keypad.6"
    KEYBOARD_KEYPAD_7 = "key.keyboard.keypad.7"
    KEYBOARD_KEYPAD_8 = "key.keyboard.keypad.8"
    KEYBOARD_KEYPAD_9 = "key.keyboard.keypad.9"
    KEYBOARD_KEYPAD_ADD = "key.keyboard.keypad.add"
    KEYBOARD_KEYPAD_DECIMAL = "key.keyboard.keypad.decimal"
    KEYBOARD_KEYPAD_ENTER = "key.keyboard.keypad.enter"
    KEYBOARD_KEYPAD_EQUAL = "key.keyboard.keypad.equal"
    KEYBOARD_KEYPAD_MULTIPLY = "key.keyboard.keypad.multiply"
    KEYBOARD_KEYPAD_DIVIDE = "key.keyboard.keypad.divide"
    KEYBOARD_KEYPAD_SUBTRACT = "key.keyboard.keypad.subtract"
    KEYBOARD_ARROW_DOWN = "key.keyboard.down"
    KEYBOARD_ARROW_LEFT = "key.keyboard.left"
    KEYBOARD_ARROW_RIGHT = "key.keyboard.right"
    KEYBOARD_ARROW_UP = "key.keyboard.up"
    KEYBOARD_APOSTROPHE = "key.keyboard.apostrophe"
    KEYBOARD_BACKSLASH = "key.keyboard.backslash"
    KEYBOARD_COMMA = "key.keyboard.comma"
    KEYBOARD_EQUAL = "key.keyboard.equal"
    KEYBOARD_GRAVE_ACCENT = "key.keyboard.grave.accent"
    KEYBOARD_LEFT_BRACKET = "key.keyboard.left.bracket"
    KEYBOARD_MINUS = "key.keyboard.minus"
    KEYBOARD_PERIOD = "key.keyboard.period"
    KEYBOARD_RIGHT_BRACKET = "key.keyboard.right.bracket"
    KEYBOARD_SEMICOLON = "key.keyboard.semicolon"
    KEYBOARD_SLASH = "key.keyboard.slash"
    KEYBOARD_SPACE = "key.keyboard.space"
    KEYBOARD_TAB = "key.keyboard.tab"
    KEYBOARD_LEFT_ALT = "key.keyboard.left.alt"
    KEYBOARD_LEFT_CONTROL = "key.keyboard.left.control"
    KEYBOARD_LEFT_SHIFT = "key.keyboard.left.shift"
    KEYBOARD_LEFT_WIN = "key.keyboard.left.win"
    KEYBOARD_RIGHT_ALT = "key.keyboard.right.alt"
    KEYBOARD_RIGHT_CONTROL = "key.keyboard.right.control"
    KEYBOARD_RIGHT_SHIFT = "key.keyboard.right.shift"
    KEYBOARD_RIGHT_WIN = "key.keyboard.right.win"
    KEYBOARD_ENTER = "key.keyboard.enter"
    KEYBOARD_ESCAPE = "key.keyboard.escape"
    KEYBOARD_BACKSPACE = "key.keyboard.backspace"
    KEYBOARD_DELETE = "key.keyboard.delete"
    KEYBOARD_END = "key.keyboard.end"
    KEYBOARD_HOME = "key.keyboard.home"
    KEYBOARD_INSERT = "key.keyboard.insert"
    KEYBOARD_PAGE_DOWN = "key.keyboard.page.down"
    KEYBOARD_PAGE_UP = "key.keyboard.page.up"
    KEYBOARD_CAPS_LOCK = "key.keyboard.caps.lock"
    KEYBOARD_PAUSE = "key.keyboard.pause"
    KEYBOARD_SCROLL_LOCK = "key.keyboard.scroll.lock"
    KEYBOARD_MENU = "key.keyboard.menu"
    PRINT_SCREEN = "key.keyboard.print.screen"
    WORLD_1 = "key.keyboard.world.1"
    WORLD_2 = "key.keyboard.world.2"


KEYCODE_OLD_TO_KEYBIND = {
    -100: Keybind.MOUSE_BUTTON_LEFT,
    -99: Keybind.MOUSE_BUTTON_RIGHT,
    -98: Keybind.MOUSE_BUTTON_MIDDLE,
    -97: Keybind.MOUSE_BUTTON_3,
    -96: Keybind.MOUSE_BUTTON_4,
    -95: Keybind.MOUSE_BUTTON_5,
    -94: Keybind.MOUSE_BUTTON_6,
    -93: Keybind.MOUSE_BUTTON_7,
    -92: Keybind.MOUSE_BUTTON_8,
    -91: Keybind.MOUSE_BUTTON_9,
    -90: Keybind.MOUSE_BUTTON_10,
    -89: Keybind.MOUSE_BUTTON_11,
    -88: Keybind.MOUSE_BUTTON_12,
    -87: Keybind.MOUSE_BUTTON_13,
    -86: Keybind.MOUSE_BUTTON_14,
    -85: Keybind.MOUSE_BUTTON_15,

    0: Keybind.NOT_BOUND,
    1: Keybind.KEYBOARD_ESCAPE,
    2: Keybind.KEYBOARD_1,
    3: Keybind.KEYBOARD_2,
    4: Keybind.KEYBOARD_3,
    5: Keybind.KEYBOARD_4,
    6: Keybind.KEYBOARD_5,
    7: Keybind.KEYBOARD_6,
    8: Keybind.KEYBOARD_7,
    9: Keybind.KEYBOARD_8,
    10: Keybind.KEYBOARD_9,
    11: Keybind.KEYBOARD_0,
    12: Keybind.KEYBOARD_MINUS,
    13: Keybind.KEYBOARD_EQUAL,
    14: Keybind.KEYBOARD_BACKSPACE,
    15: Keybind.KEYBOARD_TAB,
    16: Keybind.KEYBOARD_Q,
    17: Keybind.KEYBOARD_W,
    18: Keybind.KEYBOARD_E,
    19: Keybind.KEYBOARD_R,
    20: Keybind.KEYBOARD_T,
    21: Keybind.KEYBOARD_Y,
    22: Keybind.KEYBOARD_U,
    23: Keybind.KEYBOARD_I,
    24: Keybind.KEYBOARD_O,
    25: Keybind.KEYBOARD_P,
    26: Keybind.KEYBOARD_LEFT_BRACKET,
    27: Keybind.KEYBOARD_RIGHT_BRACKET,
    28: Keybind.KEYBOARD_ENTER,
    29: Keybind.KEYBOARD_LEFT_CONTROL,
    30: Keybind.KEYBOARD_A,
    31: Keybind.KEYBOARD_S,
    32: Keybind.KEYBOARD_D,
    33: Keybind.KEYBOARD_F,
    34: Keybind.KEYBOARD_G,
    35: Keybind.KEYBOARD_H,
    36: Keybind.KEYBOARD_J,
    37: Keybind.KEYBOARD_K,
    38: Keybind.KEYBOARD_L,
    39: Keybind.KEYBOARD_SEMICOLON,
    40: Keybind.KEYBOARD_APOSTROPHE,
    41: Keybind.KEYBOARD_GRAVE_ACCENT,
    42: Keybind.KEYBOARD_LEFT_SHIFT,
    43: Keybind.KEYBOARD_BACKSLASH,
    44: Keybind.KEYBOARD_Z,
    45: Keybind.KEYBOARD_X,
    46: Keybind.KEYBOARD_C,
    47: Keybind.KEYBOARD_V,
    48: Keybind.KEYBOARD_B,
    49: Keybind.KEYBOARD_N,
    50: Keybind.KEYBOARD_M,
    51: Keybind.KEYBOARD_COMMA,
    52: Keybind.KEYBOARD_PERIOD,
    53: Keybind.KEYBOARD_SLASH,
    54: Keybind.KEYBOARD_RIGHT_SHIFT,
    55: Keybind.KEYBOARD_KEYPAD_MULTIPLY,
    56: Keybind.KEYBOARD_LEFT_ALT,
    57: Keybind.KEYBOARD_SPACE,
    58: Keybind.KEYBOARD_CAPS_LOCK,
    59: Keybind.KEYBOARD_F1,
    60: Keybind.KEYBOARD_F2,
    61: Keybind.KEYBOARD_F3,
    62: Keybind.KEYBOARD_F4,
    63: Keybind.KEYBOARD_F5,
    64: Keybind.KEYBOARD_F6,
    65: Keybind.KEYBOARD_F7,
    66: Keybind.KEYBOARD_F8,
    67: Keybind.KEYBOARD_F9,
    68: Keybind.KEYBOARD_F10,
    69: Keybind.KEYBOARD_NUMLOCK,
    70: Keybind.KEYBOARD_SCROLL_LOCK,
    71: Keybind.KEYBOARD_KEYPAD_7,
    72: Keybind.KEYBOARD_KEYPAD_8,
    73: Keybind.KEYBOARD_KEYPAD_9,
    74: Keybind.KEYBOARD_KEYPAD_SUBTRACT,
    75: Keybind.KEYBOARD_KEYPAD_4,
    76: Keybind.KEYBOARD_KEYPAD_5,
    77: Keybind.KEYBOARD_KEYPAD_6,
    78: Keybind.KEYBOARD_KEYPAD_ADD,
    79: Keybind.KEYBOARD_KEYPAD_1,
    80: Keybind.KEYBOARD_KEYPAD_2,
    81: Keybind.KEYBOARD_KEYPAD_3,
    82: Keybind.KEYBOARD_KEYPAD_0,
    83: Keybind.KEYBOARD_KEYPAD_DECIMAL,
    87: Keybind.KEYBOARD_F11,
    88: Keybind.KEYBOARD_F12,
    100: Keybind.KEYBOARD_F13,
    101: Keybind.KEYBOARD_F14,
    102: Keybind.KEYBOARD_F15,
    112: None,
    121: None,
    123: None,
    125: None,
    141: None,
    144: None,
    145: None,
    146: None,
    147: None,
    148: None,
    149: None,
    150: None,
    151: None,
    156: Keybind.KEYBOARD_KEYPAD_ENTER,
    157: Keybind.KEYBOARD_RIGHT_CONTROL,
    179: Keybind.KEYBOARD_COMMA,
    181: Keybind.KEYBOARD_KEYPAD_DIVIDE,
    183: Keybind.PRINT_SCREEN,
    184: Keybind.KEYBOARD_RIGHT_ALT,
    197: Keybind.KEYBOARD_PAUSE,
    199: Keybind.KEYBOARD_HOME,
    200: Keybind.KEYBOARD_ARROW_UP,
    201: Keybind.KEYBOARD_PAGE_UP,
    203: Keybind.KEYBOARD_ARROW_LEFT,
    205: Keybind.KEYBOARD_ARROW_RIGHT,
    207: Keybind.KEYBOARD_END,
    208: Keybind.KEYBOARD_ARROW_DOWN,
    209: Keybind.KEYBOARD_PAGE_DOWN,
    210: Keybind.KEYBOARD_INSERT,
    211: Keybind.KEYBOARD_DELETE,
    219: Keybind.KEYBOARD_LEFT_WIN,
    220: Keybind.KEYBOARD_RIGHT_WIN,
    221: None,
    222: None,
    223: None,
}


OptBool = OnErrorOmit[bool | None]
OptFloat = OnErrorOmit[float | None]
OptInt = OnErrorOmit[int | None]
OptStr = OnErrorOmit[str | None]
OptKeybind = OnErrorOmit[Keybind | None]


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
    render_clouds: OnErrorOmit[Literal["true", "false", "fast"] | None] = Field(None, alias="renderClouds")
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
    main_hand: OnErrorOmit[Literal["left", "right"] | None] = Field(None, alias="mainHand")
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