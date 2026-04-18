use clroxide::{
    clr::Clr,
    primitives::{_Assembly, empty_variant_array, wrap_method_arguments, wrap_string_in_variant},
};
use windows::Win32::System::Com::VARIANT;
use obfstr::obfstr;

fn main() -> Result<(), String> {
    let mut clr = Clr::context_only(None)?;
    let mut context = clr.get_context()?;
    let app_domain = context.app_domain;
    let mscorlib = unsafe { (*app_domain).load_library(obfstr!("mscorlib"))? };

    unsafe {
        write_line(
            mscorlib,
            vec![
                "Hello from Console.WriteLine!\n And then: {0}",
                obfstr!("Let's substitute!\n\n"),
            ],
        )?;
    }

    unsafe {
        let output = write_to_buffer(
            mscorlib,
            vec![
                "Hello from System.IO.StringWriter!\n And then: {0}",
                obfstr!("Let's substitute!"),
            ],
        )?;

        println!("{}{}", obfstr!("Here's the buffer output:\n\n"), output)
    }

    Ok(())
}

pub unsafe fn write_line(mscorlib: *mut _Assembly, lines: Vec<&str>) -> Result<(), String> {
    let console = (*mscorlib).get_type(obfstr!("System.Console"))?;

    let mut messages: Vec<VARIANT> = vec![];

    for line in lines {
        messages.push(wrap_string_in_variant(line));
    }

    let arguments = wrap_method_arguments(messages)?;

    let instance: VARIANT = std::mem::zeroed();

    let _ = (*console).invoke_static_method(instance.clone(), obfstr!("WriteLine").into(), arguments)?;

    Ok(())
}

pub unsafe fn write_to_buffer(
    mscorlib: *mut _Assembly,
    lines: Vec<&str>,
) -> Result<String, String> {
    let string_writer = (*mscorlib).get_type(obfstr!("System.IO.StringWriter"))?;
    let write_line =
        (*string_writer).get_method_with_signature(obfstr!("Void Write(System.String, System.Object)"))?;
    let to_string = (*string_writer).get_method(obfstr!("ToString"))?;

    let mut messages: Vec<VARIANT> = vec![];

    for line in lines {
        messages.push(wrap_string_in_variant(line));
    }

    let arguments = wrap_method_arguments(messages)?;
    let instance = (*mscorlib).create_instance(obfstr!("System.IO.StringWriter"))?;

    (*write_line).invoke(arguments, Some(instance.clone()))?;

    let result = (*to_string).invoke(empty_variant_array(), Some(instance.clone()))?;

    let out = unsafe { result.Anonymous.Anonymous.Anonymous.bstrVal.to_string() };

    Ok(out)
}
