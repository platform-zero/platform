package net.datamancy.platform

/** Read-only shell guard for an imported volume; missing, linked and uncertain imports never start. */
internal object BusinessRestoreGuards {
    fun marker(root: String, sourceHash: String): String {
        require(root.matches(Regex("/[A-Za-z0-9_/-]+")) && root.split('/').none { it == ".." })
        require(sourceHash.matches(Regex("[a-f0-9]{64}")))
        return "test ! -L $root; test -d $root; " +
            "test ! -e $root/.restore-in-progress; test ! -L $root/.restore-in-progress; " +
            "test -f $root/.p0v3-restore-complete; test ! -L $root/.p0v3-restore-complete; " +
            "test \"${'$'}(stat -c %h $root/.p0v3-restore-complete)\" = 1; " +
            "test \"${'$'}(stat -c %s $root/.p0v3-restore-complete)\" = 65; " +
            "grep -qx '$sourceHash' $root/.p0v3-restore-complete"
    }
}
