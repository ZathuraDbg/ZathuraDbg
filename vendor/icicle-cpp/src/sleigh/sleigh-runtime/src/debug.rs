use crate::decoder::{DecodedConstructor, SubtableCtx};

impl std::fmt::Debug for SubtableCtx<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let constructor_id = self.constructor.id;
        let constructor = self.constructor_info();
        let constructor_line = self
            .data
            .debug_info
            .constructors
            .get(constructor_id as usize)
            .map_or("unknown", |x| x.line.as_str());

        let name =
            self.data.debug_info.subtable_names.get(constructor.table as usize).unwrap_or(&(0, 0));
        f.debug_struct("Subtable")
            .field("id", &format_args!("{} (\"{}\")", constructor.table, &self.data.get_str(*name)))
            .field("constructor_id", &constructor_id)
            .field("offset", &self.constructor.offset)
            .field("len", &self.constructor.len)
            .field("line", &constructor_line)
            .field("locals", &LocalsDebug { ctx: self, locals: self.locals() })
            .field("subtables", &SubtableListDebug { ctx: self, list: self.subtables() })
            .finish()
    }
}

struct SubtableListDebug<'a, 'b> {
    ctx: &'a SubtableCtx<'b, 'b>,
    list: &'a [DecodedConstructor],
}

impl std::fmt::Debug for SubtableListDebug<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.list.iter().map(|subtable| self.ctx.visit_constructor(*subtable)))
            .finish()
    }
}

struct LocalsDebug<'a, 'b> {
    #[allow(unused)]
    ctx: &'a SubtableCtx<'b, 'b>,
    locals: &'a [i64],
}

impl std::fmt::Debug for LocalsDebug<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for entry in self.locals {
            list.entry(&format_args!("{entry:#x}"));
        }
        list.finish()
    }
}
