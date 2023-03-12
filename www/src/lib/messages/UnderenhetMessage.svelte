<script>
    export let orgnr;

    function getMainUnitUrl(orgnr) {
        const queryParams = new URLSearchParams(window.location.search);
        queryParams.delete("query");
        queryParams.append("query", orgnr);
        queryParams.append("guidedMainOrgSearch", "true");
        return queryParams.toString();
    }
</script>

<div id="stashed-underenhet-infomessage">
    <a href="?{getMainUnitUrl(orgnr)}">
        <div class="card-panel grey lighten-4 hoverable">
            <span class="black-text"
                ><i class="material-icons">info</i>Du søkte etter en underenhet.
                Fant du ikke det du lette etter, kan det være de er utstedt til
                den tilhørende hovedenheten. Trykk her for å søke etter
                sertifikater på hovedenheten.
            </span>
        </div>
    </a>
    <br />
</div>
