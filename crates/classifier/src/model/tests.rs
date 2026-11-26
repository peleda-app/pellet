use super::*;

/// A small deterministic generator, so the corpus is the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() % items.len() as u64) as usize]
    }
}

const SHARED: [&str; 24] = [
    "the", "and", "you", "your", "this", "that", "with", "for", "have", "will", "today", "please",
    "we", "our", "about", "more", "here", "time", "new", "can", "all", "from", "just", "now",
];
const SPAM: [&str; 16] = [
    "winner",
    "free",
    "prize",
    "casino",
    "bonus",
    "claim",
    "offer",
    "discount",
    "pills",
    "loan",
    "credit",
    "urgent",
    "cheap",
    "bitcoin",
    "guaranteed",
    "limited",
];
const HAM: [&str; 16] = [
    "meeting",
    "report",
    "agenda",
    "quarterly",
    "draft",
    "notes",
    "review",
    "team",
    "project",
    "schedule",
    "lunch",
    "budget",
    "minutes",
    "feedback",
    "slides",
    "deadline",
];

fn document(rng: &mut Rng, spam: bool) -> Document {
    let special: &[&str] = if spam { &SPAM } else { &HAM };
    let body: Vec<&str> = (0..40)
        .map(|_| {
            if rng.next() % 10 < 7 {
                rng.pick(&SHARED)
            } else {
                rng.pick(special)
            }
        })
        .collect();
    let subject: Vec<&str> = (0..4).map(|_| rng.pick(special)).collect();
    Document {
        subject: subject.join(" "),
        body: body.join(" "),
        domains: vec![
            if spam {
                "offer.example.net"
            } else {
                "intranet.example.com"
            }
            .into(),
        ],
        sender_domain: if spam {
            "promo.example.net"
        } else {
            "example.com"
        }
        .into(),
        headers: vec!["From".into(), "To".into(), "Subject".into()],
        symbols: if spam && rng.next().is_multiple_of(2) {
            vec!["RBL_EXAMPLE".into()]
        } else {
            vec![]
        },
    }
}

#[test]
fn separates_unseen_spam_and_ham() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut model = Model::new(Params::default()).unwrap();
    for _ in 0..200 {
        let spam = document(&mut rng, true);
        let ham = document(&mut rng, false);
        model.train(&spam, true);
        model.train(&ham, false);
    }
    assert_eq!(model.samples(), (200, 200));
    let mut right = 0;
    let total = 200;
    for i in 0..total {
        let spam = i % 2 == 0;
        let p = model.predict(&document(&mut rng, spam));
        if (p > 0.5) == spam {
            right += 1;
        }
    }
    assert!(right * 100 >= total * 98, "{right} of {total} right");
}

#[test]
fn confident_after_training() {
    let mut rng = Rng(42);
    let mut model = Model::new(Params::default()).unwrap();
    for _ in 0..100 {
        model.train(&document(&mut rng, true), true);
        model.train(&document(&mut rng, false), false);
    }
    assert!(model.predict(&document(&mut rng, true)) > 0.9);
    assert!(model.predict(&document(&mut rng, false)) < 0.1);
}

#[test]
fn untrained_model_is_undecided() {
    let model = Model::new(Params::default()).unwrap();
    let p = model.predict(&document(&mut Rng(7), true));
    assert!((p - 0.5).abs() < 1e-9);
}

#[test]
fn memory_is_fixed_by_the_table_size() {
    let model = Model::new(Params::default()).unwrap();
    assert_eq!(model.memory_bytes(), 2 * 1024 * 1024);
    let small = Model::new(Params {
        bits: MIN_BITS,
        ..Params::default()
    })
    .unwrap();
    assert_eq!(small.memory_bytes(), 512 * 1024);
}

#[test]
fn refuses_bad_parameters() {
    for params in [
        Params {
            bits: 8,
            ..Params::default()
        },
        Params {
            bits: 30,
            ..Params::default()
        },
        Params {
            alpha: 0.0,
            ..Params::default()
        },
        Params {
            l1: -1.0,
            ..Params::default()
        },
        Params {
            beta: f32::NAN,
            ..Params::default()
        },
    ] {
        assert!(
            matches!(Model::new(params), Err(ModelError::Params(_))),
            "{params:?}"
        );
    }
}

#[test]
fn round_trips_through_bytes() {
    let mut rng = Rng(9);
    let mut model = Model::new(Params {
        bits: MIN_BITS,
        ..Params::default()
    })
    .unwrap();
    for _ in 0..20 {
        model.train(&document(&mut rng, true), true);
        model.train(&document(&mut rng, false), false);
    }
    let bytes = model.to_bytes();
    let back = Model::from_bytes(&bytes).unwrap();
    assert_eq!(back, model);
    let doc = document(&mut rng, true);
    assert_eq!(back.predict(&doc), model.predict(&doc));
}

#[test]
fn refuses_other_formats() {
    let model = Model::new(Params {
        bits: MIN_BITS,
        ..Params::default()
    })
    .unwrap();
    let bytes = model.to_bytes();
    assert_eq!(Model::from_bytes(b"not a model"), Err(ModelError::Format));
    assert_eq!(
        Model::from_bytes(&bytes[..bytes.len() - 1]),
        Err(ModelError::Format)
    );
    let mut other_version = bytes.clone();
    other_version[8..12].copy_from_slice(&(TOKENIZER_VERSION + 1).to_le_bytes());
    assert_eq!(
        Model::from_bytes(&other_version),
        Err(ModelError::Tokenizer(TOKENIZER_VERSION + 1))
    );
    let mut bad_bits = bytes;
    bad_bits[12] = 40;
    assert_eq!(Model::from_bytes(&bad_bits), Err(ModelError::Format));
}

#[test]
fn seeds_change_the_hashing() {
    assert_ne!(fnv1a(1, "w:free"), fnv1a(2, "w:free"));
    assert_eq!(fnv1a(1, "w:free"), fnv1a(1, "w:free"));
}
