use activechain_storage_profile::{render_profile_tsv, render_representative_workload_tsv};

fn main() {
    print!("{}", render_profile_tsv());
    print!(
        "{}",
        render_representative_workload_tsv().expect("frozen representative workload is valid")
    );
}
