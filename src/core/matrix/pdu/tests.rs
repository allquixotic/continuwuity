use super::Count;

#[test]
fn backfilled_parse() {
	let count: Count = "-987654".parse().expect("parse() failed");
	let backfilled = matches!(count, Count::Backfilled(_));

	assert!(backfilled, "not backfilled variant");
}

#[test]
fn normal_parse() {
	let count: Count = "987654".parse().expect("parse() failed");
	let backfilled = matches!(count, Count::Backfilled(_));

	assert!(!backfilled, "backfilled variant");
}

#[test]
fn synapse_live_room_stream_parse() {
	let count: Count = "s2633508".parse().expect("parse() failed");

	assert_eq!(count, Count::Normal(2_633_508));
}

#[test]
fn synapse_full_stream_token_parse() {
	let count: Count = "s3003120_72507853_16462_5415117_560437_250_24769_12242099_0_1432_2_1"
		.parse()
		.expect("parse() failed");

	assert_eq!(count, Count::Normal(3_003_120));
}

#[test]
fn synapse_historic_room_stream_parse() {
	let count: Count = "t426-2633508".parse().expect("parse() failed");

	assert_eq!(count, Count::Normal(2_633_508));
}

#[test]
fn synapse_multi_writer_room_stream_parse() {
	let count: Count = "m56~2.58~3.59".parse().expect("parse() failed");

	assert_eq!(count, Count::Normal(56));
}
