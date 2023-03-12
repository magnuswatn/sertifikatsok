<script>
  import HjelpButton from "./lib/buttons/HjelpButton.svelte";
  import ErrorPage from "./lib/ErrorPage.svelte";
  import ResultPage from "./lib/ResultPage.svelte";
  import SearchPage from "./lib/SearchPage.svelte";
  import Spinner from "./lib/Spinner.svelte";
  import { callApi } from "./lib/utils";
</script>

<div class="container" id="body-container">
  {#if window.location.search != ""}
    {#await callApi(window.location.search)}
      <Spinner />
    {:then response}
      <ResultPage {response} />
    {:catch error}
      <ErrorPage {error} />
    {/await}
  {:else}
    <SearchPage />
  {/if}
</div>

<HjelpButton />
