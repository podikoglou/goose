// error: 'prop' is only valid at the top level outside of functions; place properties directly above the function they specify
fn foo() {
    prop for x {
        x > 0
    }
}
