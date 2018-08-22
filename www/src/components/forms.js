import React, { Component } from 'react';
import PropTypes from 'prop-types';
import M from 'materialize-css';

// TODO: make this a controlled component instead?

export class SearchForm extends Component {
    constructor(props) {
        super(props);
        this.ref = React.createRef();
    }

    componentDidMount() {
        this.self = M.Autocomplete.init(this.ref.current, { 'limit': 20 })
    }

    componentDidUpdate() {
        this.self.updateData(this.props.data);
        this.self.open();
        this.ref.current.focus();
    }

    componentWillUnmount() {
        this.self.destroy();
        this.self = null;
    }

    render() {
        return (
            <div className="row">
                <div className="col s12">
                    <div className="row">
                        <div className="input-field col s12">
                            <input ref={this.ref} type="text" autoFocus onChange={() => this.props.onChange(this.ref.current.value)} />
                            <label htmlFor="autocomplete-input">
                                <i className="material-icons">search</i>
                                {this.props.text}</label>
                        </div>
                    </div>
                </div>
            </div>
        )
    }
}

SearchForm.propTypes = {
    text: PropTypes.string,
    onChange: PropTypes.func,
    data: PropTypes.object,
}
