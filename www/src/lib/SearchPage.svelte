<script>
    import { onMount } from "svelte";
    import {
        getCompanies,
        getEnterpriseSearchValue,
        isBrregSearchable,
    } from "./utils";

    let enterpriseSearchTab;
    let searchTimeout;
    let autocompleteInst;
    let tabs;

    let enterpriseInput;
    let personInput;

    onMount(() => {
        window.M.Tabs.init(tabs, {
            onShow: (t) => setActive(t.id),
        });
        autocompleteInst = window.M.Autocomplete.init(enterpriseInput);

        enterpriseInput.focus();
    });

    const handleEnterpriseInput = async function (e) {
        if (searchTimeout) {
            window.clearTimeout(searchTimeout);
        }
        searchTimeout = window.setTimeout(async function () {
            const searchValue = enterpriseInput.value.split("'").join("");
            if (isBrregSearchable(searchValue)) {
                const companies = await getCompanies(searchValue);

                autocompleteInst.updateData(companies);
                autocompleteInst.open();
            }
        }, 500);
    };

    const handleSearchKey = (e) => {
        e.currentTarget.classList.remove("invalid");
        if (e.key === "Enter") {
            // Only trigger search if the user is not
            // just choosing an autocomplete suggestion.
            if (autocompleteInst.activeIndex === -1) {
                handleSearch("prod");
            }
        }
    };

    function handleSearch(env) {
        let type;
        let query;
        if (enterpriseSearchTab.className === "active") {
            type = "enterprise";
            query = getEnterpriseSearchValue(enterpriseInput.value);
            if (query === "") {
                enterpriseInput.classList.add("invalid");
                return;
            }
        } else {
            type = "personal";
            query = personInput.value;
            if (query === "") {
                personInput.classList.add("invalid");
                return;
            }
        }

        const queryParams = new URLSearchParams([
            ["query", query],
            ["env", env],
            ["type", type],
        ]);
        window.location.search = queryParams.toString();
    }

    function setActive(input) {
        if (input === "enterprise") {
            if (personInput.value !== "") {
                enterpriseInput.value = personInput.value;
            }
            enterpriseInput.focus();
        } else {
            if (enterpriseInput.value !== "") {
                personInput.value = enterpriseInput.value;
            }
            personInput.focus();
        }
    }
</script>

<div>
    <br />
    <div class="card">
        <div class="card-tabs">
            <ul class="tabs tabs-fixed-width" bind:this={tabs}>
                <li class="tab">
                    <a
                        class="active"
                        id="enterprise-search"
                        href="#enterprise"
                        bind:this={enterpriseSearchTab}
                    >
                        Virksomhet
                    </a>
                </li>
                <li class="tab">
                    <a
                        href="#person"
                        id="person-search"
                        on:click={() => setActive("person")}>Person</a
                    >
                </li>
            </ul>
        </div>
        <div class="card-content">
            <div id="enterprise">
                <div class="row">
                    <div class="input-field col s12">
                        <input
                            type="text"
                            id="enterprise-search-input"
                            class="autocomplete"
                            bind:this={enterpriseInput}
                            on:input={handleEnterpriseInput}
                            on:keydown={handleSearchKey}
                        />
                        <label for="enterprise-search-input">
                            <i class="material-icons">search</i>
                            Organisasjonsnummer eller -navn
                        </label>
                    </div>
                </div>
            </div>
            <div id="person">
                <div class="row">
                    <div class="input-field col s12">
                        <input
                            type="text"
                            id="person-search-input"
                            class="search-box"
                            bind:this={personInput}
                            on:keydown={handleSearchKey}
                        />
                        <label for="person-search-input">
                            <i class="material-icons">search</i>
                            Fullt navn eller e-postadresse
                        </label>
                    </div>
                </div>
            </div>
            <div class="center">
                <button
                    class="btn waves-effect waves-light valign-wrapper"
                    id="search-button"
                    on:click={() => handleSearch("prod")}>Søk</button
                >
                <button
                    class="btn waves-effect waves-light valign-wrapper"
                    id="search-test-button"
                    on:click={() => handleSearch("test")}>Søk i test</button
                >
            </div>
        </div>
    </div>
</div>
