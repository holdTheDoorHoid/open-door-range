//! Assembling a world, and two benches that assemble themselves.
//!
//! [`WorldBuilder`] is a thin fluent layer over [`World`]'s own `add_*`
//! methods. It exists so a scenario reads as a description of a door rather
//! than as a sequence of handle juggling, and because the order links and taps
//! are attached in is load-bearing (see [`crate::link`]) — the builder makes
//! that order explicit.
//!
//! [`wiegand_bench`] and [`osdp_bench`] are the two configurations almost every
//! drill starts from. They exist so that a drill, a test or `odr-scenario` can
//! get to the interesting part in one line.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use odr_wiegand::{ClockDataTiming, WiegandTiming};

use crate::access::AccessList;
use crate::controller::{AcuConfig, Controller};
use crate::door::Door;
use crate::error::Result;
use crate::ids::{ControllerId, DoorId, LinkId, Micros, ReaderId, TapId};
use crate::link::Rs485Timing;
use crate::reader::{ClockDataConfig, PdConfig, Reader, ReaderProtocol};
use crate::tap::Tap;
use crate::world::{TapPosition, World};

/// A fluent assembler for a world.
#[derive(Debug)]
pub struct WorldBuilder {
    world: World,
}

impl WorldBuilder {
    /// Start an empty world with a seed.
    pub fn new(seed: u64) -> WorldBuilder {
        WorldBuilder {
            world: World::new(seed),
        }
    }

    /// The world under construction.
    pub fn world(&self) -> &World {
        &self.world
    }

    /// The world under construction, mutably.
    pub fn world_mut(&mut self) -> &mut World {
        &mut self.world
    }

    /// Add a door.
    pub fn door(&mut self, name: impl Into<String>, strike_time_us: Micros) -> DoorId {
        let d = Door::new(DoorId(0), name).with_strike_time(strike_time_us);
        self.world.add_door(d)
    }

    /// Add a legacy panel, which listens to a two-wire link and cannot talk
    /// back.
    pub fn legacy_panel(&mut self, name: impl Into<String>, access: AccessList) -> ControllerId {
        let c = Controller::legacy(ControllerId(0), name).with_access(access);
        self.world.add_controller(c)
    }

    /// Add an OSDP controller.
    pub fn osdp_controller(
        &mut self,
        name: impl Into<String>,
        config: AcuConfig,
        access: AccessList,
    ) -> ControllerId {
        let c = Controller::osdp(ControllerId(0), name, config).with_access(access);
        self.world.add_controller(c)
    }

    /// Add a Wiegand reader.
    pub fn wiegand_reader(&mut self, name: impl Into<String>) -> ReaderId {
        self.world
            .add_reader(Reader::new(ReaderId(0), name, ReaderProtocol::Wiegand))
    }

    /// Add a clock-and-data reader.
    pub fn clock_data_reader(
        &mut self,
        name: impl Into<String>,
        config: ClockDataConfig,
    ) -> ReaderId {
        self.world.add_reader(Reader::new(
            ReaderId(0),
            name,
            ReaderProtocol::ClockData(config),
        ))
    }

    /// Add an OSDP peripheral device.
    pub fn osdp_pd(&mut self, name: impl Into<String>, config: PdConfig) -> ReaderId {
        self.world.add_reader(Reader::new(
            ReaderId(0),
            name,
            ReaderProtocol::Osdp(Box::new(config)),
        ))
    }

    /// Run a Wiegand pair between a controller and a reader.
    pub fn wiegand_link(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        reader: ReaderId,
        timing: WiegandTiming,
    ) -> Result<LinkId> {
        self.world
            .add_wiegand_link(name, controller, reader, timing)
    }

    /// Run a clock-and-data pair between a controller and a reader.
    pub fn clock_data_link(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        reader: ReaderId,
        timing: ClockDataTiming,
    ) -> Result<LinkId> {
        self.world
            .add_clock_data_link(name, controller, reader, timing)
    }

    /// Run an RS-485 bus from a controller.
    pub fn rs485_bus(
        &mut self,
        name: impl Into<String>,
        controller: ControllerId,
        timing: Rs485Timing,
    ) -> Result<LinkId> {
        self.world.add_rs485_bus(name, controller, timing)
    }

    /// Hang a peripheral off an RS-485 bus, beyond everything already on it.
    pub fn attach_pd(&mut self, link: LinkId, reader: ReaderId) -> Result<&mut Self> {
        self.world.attach_pd(link, reader)?;
        Ok(self)
    }

    /// Wire a controller to a door.
    pub fn attach_door(&mut self, controller: ControllerId, door: DoorId) -> Result<&mut Self> {
        self.world.attach_door(controller, door)?;
        Ok(self)
    }

    /// Clip a tap onto a link at the controller end.
    pub fn tap(&mut self, link: LinkId, tap: Box<dyn Tap>) -> Result<TapId> {
        self.world.add_tap(link, tap)
    }

    /// Clip a tap onto a link at a chosen position.
    pub fn tap_at(
        &mut self,
        link: LinkId,
        tap: Box<dyn Tap>,
        position: TapPosition,
    ) -> Result<TapId> {
        self.world.add_tap_at(link, tap, position)
    }

    /// Start a controller polling.
    pub fn start_polling(&mut self, controller: ControllerId, at_us: Micros) -> Result<&mut Self> {
        self.world.start_polling(controller, at_us)?;
        Ok(self)
    }

    /// Finish, handing back the world.
    pub fn build(self) -> World {
        self.world
    }
}

/// A complete legacy bench: card, reader, wire, panel, door.
#[derive(Debug)]
pub struct WiegandBench {
    /// The world.
    pub world: World,
    /// The reader.
    pub reader: ReaderId,
    /// The panel.
    pub controller: ControllerId,
    /// The door.
    pub door: DoorId,
    /// The D0/D1 pair between them.
    pub link: LinkId,
}

/// Build the Module 1 bench: one reader, one wire, one panel, one door.
///
/// ```
/// use odr_bus::{wiegand_bench, AccessList, Presentation, SourceId};
/// use odr_wiegand::{CardFormat, Credential};
///
/// let card = Credential::new(CardFormat::H10301, 42, 1337);
/// let access = AccessList::new().with_credential(&card).unwrap();
/// let mut bench = wiegand_bench(1, access).unwrap();
/// let p = Presentation::from_credential(SourceId(0), &card).unwrap();
/// bench.world.present(bench.reader, 1_000_000, p).unwrap();
/// bench.world.run_until(2_000_000).unwrap();
/// assert_eq!(bench.world.door(bench.door).unwrap().strike_count, 1);
/// ```
pub fn wiegand_bench(seed: u64, access: AccessList) -> Result<WiegandBench> {
    let mut b = WorldBuilder::new(seed);
    let door = b.door("front door", 3_000_000);
    let controller = b.legacy_panel("panel", access);
    let reader = b.wiegand_reader("reader");
    let link = b.wiegand_link("D0/D1", controller, reader, WiegandTiming::default())?;
    b.attach_door(controller, door)?;
    Ok(WiegandBench {
        world: b.build(),
        reader,
        controller,
        door,
        link,
    })
}

/// A complete legacy bench on a clock-and-data pair.
#[derive(Debug)]
pub struct ClockDataBench {
    /// The world.
    pub world: World,
    /// The reader.
    pub reader: ReaderId,
    /// The panel.
    pub controller: ControllerId,
    /// The door.
    pub door: DoorId,
    /// The CLOCK/DATA pair.
    pub link: LinkId,
}

/// Build the drill 1.6 bench: the same door on clock-and-data.
pub fn clock_data_bench(
    seed: u64,
    access: AccessList,
    reader_config: ClockDataConfig,
) -> Result<ClockDataBench> {
    let mut b = WorldBuilder::new(seed);
    let door = b.door("front door", 3_000_000);
    let controller = b.legacy_panel("panel", access);
    let reader = b.clock_data_reader("reader", reader_config);
    let link = b.clock_data_link("clock/data", controller, reader, ClockDataTiming::default())?;
    b.attach_door(controller, door)?;
    Ok(ClockDataBench {
        world: b.build(),
        reader,
        controller,
        door,
        link,
    })
}

/// What an OSDP bench should contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsdpBenchSpec {
    /// The controller's configuration.
    pub acu: AcuConfig,
    /// One entry per peripheral on the bus, in order from the controller.
    pub pds: Vec<PdConfig>,
    /// Line parameters.
    pub timing: Rs485Timing,
    /// The access list.
    pub access: AccessList,
    /// When polling starts.
    pub start_polling_at_us: Micros,
}

impl Default for OsdpBenchSpec {
    fn default() -> OsdpBenchSpec {
        OsdpBenchSpec {
            acu: AcuConfig::polling([0x01]),
            pds: alloc::vec![PdConfig::at(0x01)],
            timing: Rs485Timing::default(),
            access: AccessList::new(),
            start_polling_at_us: 0,
        }
    }
}

/// A complete OSDP bench.
#[derive(Debug)]
pub struct OsdpBench {
    /// The world.
    pub world: World,
    /// The controller.
    pub controller: ControllerId,
    /// The door.
    pub door: DoorId,
    /// The bus.
    pub link: LinkId,
    /// The peripherals, in the order they were attached.
    pub pds: Vec<ReaderId>,
}

impl OsdpBench {
    /// The first peripheral, which is the only one in most scenarios.
    pub fn pd(&self) -> ReaderId {
        self.pds.first().copied().unwrap_or(ReaderId(0))
    }
}

/// Build the Module 2 and 3 bench: one controller, one bus, one or more
/// peripherals, one door.
pub fn osdp_bench(seed: u64, spec: OsdpBenchSpec) -> Result<OsdpBench> {
    let mut b = WorldBuilder::new(seed);
    let door = b.door("front door", 3_000_000);
    let controller = b.osdp_controller("acu", spec.acu, spec.access);
    let link = b.rs485_bus("rs485", controller, spec.timing)?;
    let mut pds = Vec::new();
    for (i, cfg) in spec.pds.into_iter().enumerate() {
        let name = alloc::format!("pd{i}");
        let addr = cfg.address;
        let r = b.osdp_pd(name, cfg);
        b.attach_pd(link, r)?;
        let _ = addr;
        pds.push(r);
    }
    b.attach_door(controller, door)?;
    b.start_polling(controller, spec.start_polling_at_us)?;
    Ok(OsdpBench {
        world: b.build(),
        controller,
        door,
        link,
        pds,
    })
}
