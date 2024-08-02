//! xlsx functions
use xlsxwriter::{prelude::*};

fn new_workbook(fname: &String) -> Result<Workbook, XlsxError> {
    Workbook::new(fname)
}

fn new_sheet<'a>(
    workbook: &'a Workbook,
    sheet_name: &'a String,
) -> Result<Worksheet<'a>, XlsxError> {
    workbook.add_worksheet(Some(sheet_name))
}
