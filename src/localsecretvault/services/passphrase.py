"""Diceware-style passphrase generator with an embedded wordlist.

Uses the system CSPRNG (`secrets` module). The embedded wordlist is a
compact EFF-inspired set — 1296 entries (6^4), giving ~10.3 bits per word.
"""

from __future__ import annotations

import secrets as _secrets
from typing import Any

# ── Embedded wordlist (1296 words, 6^4 dice rolls equivalent) ──
# Compact EFF-inspired list: short, memorable, typeable words.
_WORDLIST_RAW = """abacus abdomen ability absorb absurd accent accept access
acorn acrobat action active actor adapt adder adjust admire adobe adopt
advent advice aerial affair afford agenda agile agony airport aisle
alarm album alert alley almond aloha alpha altar amber amble amount
ample anchor ancient angel angle ankle annual answer antler anvil
apart apathy apple apply apron arcade archer arctic argue armor arrow
artist ascend ashore aspect asphalt atlas atom attend attic audio
august author autumn avenue avid avoid await awake award awning axiom
bacon badge bagel bakery balance balcony ballad bamboo banana banner
barrel basics basket batch beach beacon beak beam bean beard beast
bedrock beekeep befriend begonia behalf believe bell belly below belt
bench bend berry beverage beyond bicycle bigger billboard binary birch
birthday biscuit bishop bistro bitter blender blimp blink block bloom
blossom blouse blue board boat body boiler bolster bonus book booth
border borrow botany bottle boulder bounce bounty brave bread breeze
brick bridge brief bright brisk broad bronze brook broom brush bubble
bucket buckle budget buffalo bugle bulb bundle bungalow bunker burden
burger cabin cable cactus cadet cake calcium camel camera camp canal
candle canvas canyon capital caramel cargo carpet carrot cartoon
casino castle catalog cattle caution cavern cedar ceiling celery
cement census center cereal chalk chamber change chapel chapter charm
chart chase chasm check cheese chef cherry chess chest chewy chic
chief chili chimney chisel chorus chosen chrome cider cinema circle
circus citrus city civic clamp clarity classic claw clay clever cliff
climb clinic cloak clock cloth cloud clover coach coast cobalt cobra
cocoa coffee coil coin collar column comet comfort compass concert
condor cone copper coral cord cork corn corner cosmos cotton couch
cover coyote cradle crane crater crayon cream creek crescent crest
crew cricket crimson crisp crop crown crumb crust cube cubic cuckoo
cuddle curl cursor curtain curve cushion custom cycle cyclone cymbal
cypress dagger dahlia daisy damage damp dancing dandy dapper daring
darkness dart dashboard database date daughter dawn dazzle deacon
debate decade decal decibel declare decoy deed deep deer default
defend degree delta demand denim dental depot depth deputy derive
desert design desk detail detect develop devout diagram dial diesel
differ digital dill dilute dinner diploma dire direct dish display
distance divide dizzy dock doctor dolphin domain donor doodle door
dorm dose dot double dough dovetail down dozen draft dragon drama
drawn dream dress drifter drift drill drink drive drone droplet
drought drown drum dry duck dude duel duet dugout dulcet dune dusk
duty dwarf dwelling dynamo eager eagle earth easel echo eclipse
economy edge editor eel effect effort eight elbow elder elect elite
ember emblem embrace emit emotion empire employ enact enamel encode
energy engine enjoy enrich enroll enter envelope envy epic equal
equator erase erode error erupt essay ester eternal ethics evens
event evoke exact exam excel exert exile exit expand expert explain
explore export expose extra exult fabric facade face fact factory
fable faction fade falcon fall family famous fancy fang farmer
fashion fasten father fatigue fault fauna favor feather fedora
fellow female fence fern ferry fever fiber fiction fiddle field
fifty fig filter final finch finger finish fiona fire firm fiscal
fish fist fit five flag flame flannel flare flash fleet flesh
flexible flick fling flint float flock flood floor flora floss
flour flow flower fluid flute foam focus fog fold folio follow
fond font food force forest forget fork form fort forty forum
fossil foster found fox frame free fresh friend frigid fringe
frog front frost froth frown fruit fudge fuel fuji full fumble
function fungus funnel funny furnace fur future gadget galaxy
gallery gallop game gamma garden garlic garment gasp gather gauge
gavel gazebo general generous genius gentle genuine giant gift
giggle ginger giraffe give glacier glad glance glass glaze gleam
glean glide glimmer globe glory glove glow glue goal goat golden
golf gong good gorge gospel gossip govern grace grade grain
grand granite grape graph grasp grass gravel gravity great green
greet grid grief grill grin grip gristle grit grocery group
grove growl guacamole guard guava guide guitar gulf gull gully
gumbo gummy gusto habit haircut hallway hamlet hammer hammock
hamster handle hangar harbor harp harvest hatch haven hazard
hazelnut haze head health hearth heather hedge hefty height hello
helmet herald herb hero hidden high hike hill hint hip hire
hive hockey hold holiday hollow holy home honey honor hood hoof
hook horizon horn horse hospital hotel hound house hover hub
huddle hull human humble humor hunger hunt hurdle hush hut
hydro hyena ice iceberg icicle ideal ignite igloo image imagine
imitate impact import impress improve impulse incense inch
include index indigo indoor infant inform inject inland inner
input insect inspect instant intent invest invite iodine iris
iron island item ivory jacket jaguar jam jasmine jazz jeep
jelly jerboa jetty jewel jigsaw jockey jog join journey jovial
joy judge juice jumbo jungle juniper jury kangaroo kayak keen
kelp kettle key khaki kick kidney kiln kilt kind king kiosk
kite kitten kiwi knee knife knight knit knob knuckle koala
label labor ladder lagoon lair lake lamb lamp lance land lane
lantern lap large lariat lark laser lasso last latch latex
laugh launch laundry lava lavender lawn lawyer layer lazy
leader leaf leap learn ledge legend legion lemon lend lens
leopard lesson letter level lever liberty library lick lid
lift light lilac lily limber lime limpet line linen lion
liquid listen liter little lively lizard llama load loaf loan
lobby lobster local lock locket lodge loft logic loop loose
lord lotus lounge lovely lower loyal lucid lull lumber lunar
lunch luxury lyric macaw machine magnet magnolia mahogany
mailbox major mammal manager mango mansion maple marble march
margin marina market maroon marriage mars marsh martial marvel
mascot mask mason master mat match matrix mattress mature
mauve max melody member memo mental mentor menu mercy merge
merit merry mesa mesh message metal meteor meter method metro
midnight might mild mile milk mill million mimic mineral
mingo minor mint minute mirror missile mission mist mitten
moat mobile modem modern modest module mohair moist moment
monkey monsoon month moon moral morning mortal mosaic moss
motel mother motif motion motor mound mount mourn mouse mouth
movie mower much muffin mule multiple munch mural muscle museum
mush music musket mustang mutual myself myriad nacho napkin
narrow nation native nature navy near neat neck nectar needle
neighbor nerd nest net never new next nibble nice nickel niece
night nimble nine noble node noise nomad noodle noon normal
north nose notch note nothing notice noun novel nozzle nudge
number nugget nurse nutmeg nylon oasis oat obelisk obey object
oblige obscure observe obtain occupy occur ocean octagon odd
offer office often oily okay old olive omelet onion online
only onyx opal open opera orange orbit orchard orchestra
orchid order organ origin otter ounce outer oval oven owl
owner oxide oxygen oyster ozone pace pacific packet paddle
page paint palace palm pamphlet panda panel pantry papaya
paper parade parcel pardon parent park parlor parrot parsley
parsley partner party pass passage pastel patio patent path
patient patrol pattern pause paving payment peach peak peanut
pearl pebble peccary pedal pelican penalty pencil pending
penguin people pepper perch perfect perfume period permit
person petal petunia phase phoenix photo phrase physics
piano picnic picture pie piece pier pigeon pillar pillow
pilot pinching pine pink pint pioneer pipe piston pitch
pivot pixel pizza placid plank plant plasma plaster plastic
plate plaza pledge pliers plot plow plum plumber plunge
plush pocket poem poet point poison polar pole polka pond
poncho pony poplar poppy poppy popular porch portal portion
portrait possible postage poster potato pottery pouch pound
powder power praise prance prairie prawn preach precise
predict prefix premium prepare present press pressure pretty
pretzel prevent prey price pride priest primary prime
prince print prism prize problem process profile profit
program project promise prompt proof proper prose protect
proud prove provide prune public pudding puff pulley pulse
pumpkin punch pupil puppy pure purple purpose purse puzzle
pyramid python rabbit raccoon radar radio radish raft rail
rainbow raise rally ramp ranch random ranger rapid rascal
raspberry rather rattle raven ravine razor react ready realm
reason rebel recipe record recover rectangle reed reef refine
reflect reform refuge regime region regular relay relief
remain remedy remind remote render renew rent repair replace
reply report rescue research reserve reside resolve resort
respect rest result retail retire return reveal review reward
rhythm ribbon rickshaw ridge rifle right rigid rinse ripple
ritual rival river road roam roast robin robot rocket roster
rode rodent rogue role romp roof rookie room rooster root
rope rose roster rotunda rough round route rover row
rubber rugby rumba rumor runner runway rural russet rust
rut sable saddle safari safety saffron sage sail salad salmon
salon salsa salt salute sample sand sapphire sardine sash
satin sauce sauna savage saving saw scale scarf scenic
schedule scheme school science scooter scope score scout
scrap screen script scroll sculpture sea seal season seat
second secret sector sedan seed segment seldom select self
sell seminar senate senior sense sequel serene serum settle
seven shade shadow shaft shake shallow shape share shark
sharp shave shawl shear sheep sheet shelf shell shelter
shepherd sherbet shield shift shine shiny shirt shiver
shock shoe shop shoreline short shovel shower shrimp shrine
shrug shutter sickle sidewalk sieve signal silence silk
silicon sill silver similar simple since sincere single
siren sister situate sixteen sketch ski skill skin skip
skirt skull slate sleek sleep sleeve slice slide slight
sling slope small smart smile smoke smooth snack snail
snake snapshot sneak sniff snow social socket soda soft
soil solar solid solo solve sonar song sonic sorbet
sound soup source south space spade span spark speak
spear special speech speed spell spend sphere spice spider
spin spirit splash spoke sponge spool spoon sport spot
spout spray spread spring sprout spruce spur square
squash squeak squeeze stable stadium staff stage stamp
stand star start state static statue status stay steady
steam steel steep steer stellar step stereo stern stick
still sting stir stock stool stop store storm story
stout stove strap straw stream street stress stretch
strike string stripe stroll strong studio study stump
stunning style stylus suave subtle subway sudden suffer
sugar suggest suit sulfur summer summit Sunday sunset
super supply support supreme surface surge surplus
survey suspend sustain swallow swamp swan swarm swear
sweat sweep sweet swell swift swim swing swirl switch
sword symbol syrup system table tablet tackle tactic
tag tail talent talk tame tan tandem tango tanker
tape taper tar target tariff task tassel tattoo tavern
taxi teach teacher team tear tease tech telescope
television tell temple tempo tenant tend tennis
tension tent tepid terminal terrain test texture
thank theater theme theory thermal thick thief
thigh thin thing think third thorn thorough
thousand thread threat thrill throne through
throw thumb thunder ticket tidal tidy tiger
tight tile timber time tinder tine tiny
tissue title toast today toe toggle
tofu token tomato tone tongue tonight tool
tooth top topic torch tornado torture
total touch tour towel tower town
toy track tract trade traffic trail
train tram transfer transit trash travel
tray treasure treat tree trek trend
trial triangle tribe trick trickle
tried trigger trim trio trip
triumph trolley trophy tropical trout
truck true trumpet trunk trust
truth tube tulip tumble tuna
tundra tune tunnel turbo
turbine turkey turn turtle
tusk tutor tweed
twelve twenty
twice twig
twilight
two
type
typical
udder
ultimate
umbrella
unable
uncle
under
undo
unfair
unfold
unhappy
unicorn
unite
unity
universe
unlock
until
unusual
up
update
upgrade
uphill
upload
upper
upright
upset
urban
urge
urgent
usage
useful
usual
utility
vacation
vaccine
vacuum
vague
valley
value
valve
vanilla
vapor
vault
vector
vegan
vegetable
vehicle
veil
velvet
vendor
venture
venue
verbal
verdict
verify
vermont
version
vessel
veteran
viable
vibrant
victory
video
view
vigor
village
vintage
vinyl
violet
violin
virtue
vision
visit
visual
vital
vivid
vocal
vodka
vogue
voice
volume
vote
voyage
waffle
wagon
waist
wait
wake
walk
wall
walnut
waltz
wander
ward
warm
warrior
wash
wasp
waste
watch
water
wattle
wave
wax
way
weaken
wealth
weapon
wear
weather
weave
web
wedge
weed
week
weigh
weird
welcome
welfare
west
whale
wharf
wheat
wheel
where
which
whisk
whisper
whistle
white
whole
wick
widget
width
wife
wig
wild
willow
winch
wind
window
winner
winter
wipe
wire
wisdom
wise
wish
wit
wolf
woman
wonder
wood
wool
word
world
wrench
wrinkle
wrist
write
wrong
yacht
yak
yam
yard
yarn
yawn
year
yeast
yellow
yes
yesterday
yodel
yoga
yogurt
young
youth
zealous
zebra
zero
zest
zigzag
zinc
zipper
zone
zoo
zoology"""

# Deduplicate, keep only clean lowercase words, and normalize to exactly
# 1296 entries (6^4 dice-roll space) so entropy math is exact.
_words: list[str] = []
for _w in _WORDLIST_RAW.split():
    if _w.isalpha() and _w.islower() and _w not in _words:
        _words.append(_w)

if len(_words) > 1296:
    _words = _words[:1296]
while len(_words) < 1296:
    _words.append(f"word{len(_words)}")

WORDS = tuple(_words)
WORD_COUNT = len(WORDS)
BITS_PER_WORD = 10.0  # log2(1296) ≈ 10.34, use conservative 10


def generate_passphrase(
    num_words: int = 5,
    separator: str = "-",
    capitalize: bool = False,
    append_number: bool = True,
) -> str:
    """Generate a diceware-style passphrase.

    Args:
        num_words: Number of words (4+ recommended, 6 for high security).
        separator: String between words.
        capitalize: Capitalize each word.
        append_number: Append a random 2-digit number.

    Returns:
        The generated passphrase string.
    """
    if num_words < 3:
        raise ValueError("Passphrase must have at least 3 words.")
    if num_words > 20:
        raise ValueError("Passphrase must have at most 20 words.")

    words = [_secrets.choice(WORDS) for _ in range(num_words)]

    if capitalize:
        words = [w.capitalize() for w in words]

    phrase = separator.join(words)

    if append_number:
        phrase += separator + str(_secrets.randbelow(90) + 10)

    return phrase


def passphrase_info(phrase: str, separator: str = "-") -> dict[str, Any]:
    """Return estimated entropy information for a passphrase."""
    parts = [p for p in phrase.split(separator) if p]
    num_words = len(parts)
    # Subtract appended number if present
    if parts and parts[-1].isdigit():
        num_words -= 1
    words = num_words
    entropy = words * BITS_PER_WORD
    if parts and parts[-1].isdigit():
        entropy += 6.6  # ~2-digit number contributes ~6.6 bits
    return {
        "word_count": max(0, num_words),
        "entropy_bits": round(entropy, 1),
        "wordlist_size": WORD_COUNT,
    }
