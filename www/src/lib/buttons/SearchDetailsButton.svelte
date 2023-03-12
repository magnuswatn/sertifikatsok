<script>
    export let search_details;

    import StringModal from "../modals/StringModal.svelte";

    let modalOpen = false;
</script>

<button
    class="link-text"
    id="searchDetailsTxt"
    on:click={() => (modalOpen = true)}
>
    Trykk her for å se søkedetaljer
    <i class="material-icons tiny">info_outline</i>
</button>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h5>Søkedetaljer</h5>
        <table class="bordered">
            <thead>
                <tr>
                    <th />
                    <th />
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><b>Miljø</b></td>
                    <td>{search_details["Miljø"]}</td>
                </tr>
                <tr>
                    <td><b>Sertifikattype</b></td>
                    <td>{search_details["Sertifikattype"]}</td>
                </tr>
                <tr>
                    <td><b>Søketype</b></td>
                    <td>{search_details["Søketype"]}</td>
                </tr>
                <tr>
                    <td><b>Søkefilter</b></td>
                    <td>{search_details["Søkefilter"]}</td>
                </tr>
                <tr>
                    <td><b>LDAP-servere forespurt</b></td>
                    <td>{search_details["LDAP-servere forespurt"]}</td>
                </tr>
                <tr>
                    <td><b>Korrelasjonsid</b></td>
                    <td>{search_details["Korrelasjonsid"]}</td>
                </tr>
            </tbody>
        </table>
    </StringModal>
{/if}

<style>
    .link-text {
        cursor: pointer;
        display: inline-block;
        background: none;
        margin: 1em;
        border: none;
    }
    .link-text:focus-visible {
        outline: 2px solid;
        border-radius: 3px;
    }
</style>
