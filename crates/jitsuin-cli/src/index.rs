//! `jitsuin index` (HNK-08.T2): the public rate index, recomputed from the board by anyone
//! with its viewing key. The numbers come from `jitsuin_board::rate_index`; this module only
//! prints them.

use jitsuin_core::index::{discount_class, tenor_class, DISCOUNT_CLASSES, TENOR_CLASSES};
use jitsuin_core::RateIndex;
use serde_json::{json, Value};

use crate::board::Board;

pub fn run(board: &Board, k: usize) -> RateIndex {
    jitsuin_board::rate_index(&board.collected.records, k)
}

fn label(class: Option<&jitsuin_core::index::Class>) -> &'static str {
    class.map_or("?", |c| c.label)
}

pub fn render_text(board: &Board, i: &RateIndex) -> String {
    let mut s = board.origin.describe();
    s += &format!(
        "Index    public rate index, k = {k}: a class is shown only with at least {k} invoices\n",
        k = i.k
    );
    s += &format!(
        "         {} register entries, {} invoices (each N once, first entry), {} not disclosed, \
         {} invalid\n\n",
        i.entries, i.invoices, i.undisclosed, i.invalid
    );
    s += "  tenor          invoices  median discount  discount classes (invoices)\n";
    for row in &i.tenors {
        let tenor = label(tenor_class(row.tenor));
        match &row.published {
            None => {
                s += &format!(
                    "  {tenor:<14} {:<9} {:<16} fewer than {} invoices\n",
                    "-", "-", i.k
                )
            }
            Some(p) => {
                let mut parts: Vec<String> = p
                    .discounts
                    .iter()
                    .map(|d| format!("{}: {}", label(discount_class(d.discount)), d.invoices))
                    .collect();
                if p.other > 0 {
                    parts.push(format!("other: {}", p.other));
                }
                s += &format!(
                    "  {tenor:<14} {:<9} {:<16} {}\n",
                    p.invoices,
                    label(discount_class(p.median_discount)),
                    parts.join(", ")
                );
            }
        }
    }
    s
}

pub fn render_json(board: &Board, i: &RateIndex) -> Value {
    let class = |c: &jitsuin_core::index::Class| json!({ "class": c.code, "label": c.label, "min": c.min, "max": c.max });
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "board": board.origin.to_json(),
        "k": i.k,
        "entries": i.entries,
        "invoices": i.invoices,
        "undisclosed": i.undisclosed,
        "invalid": i.invalid,
        "tenors": i.tenors.iter().map(|row| match &row.published {
            None => json!({
                "tenor": row.tenor,
                "label": label(tenor_class(row.tenor)),
                "published": false,
            }),
            Some(p) => json!({
                "tenor": row.tenor,
                "label": label(tenor_class(row.tenor)),
                "published": true,
                "invoices": p.invoices,
                "median_discount": {
                    "class": p.median_discount,
                    "label": label(discount_class(p.median_discount)),
                },
                "discounts": p.discounts.iter().map(|d| json!({
                    "class": d.discount,
                    "label": label(discount_class(d.discount)),
                    "invoices": d.invoices,
                })).collect::<Vec<_>>(),
                "other": p.other,
            }),
        }).collect::<Vec<_>>(),
        "classes": {
            "discount_bps": DISCOUNT_CLASSES.iter().map(class).collect::<Vec<_>>(),
            "tenor_days": TENOR_CLASSES.iter().map(class).collect::<Vec<_>>(),
        },
    })
}
