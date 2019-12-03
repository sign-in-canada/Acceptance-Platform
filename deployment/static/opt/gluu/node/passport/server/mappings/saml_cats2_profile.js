module.exports = profile => {
        return {
                uid: profile.nameID,
                persistentId: profile.spNameQualifier+'|'+profile.nameQualifier+'|'+profile.nameID
        }
}
